// index.js
require('dotenv').config();          // loads .env locally (development only)

const express = require('express');
const cors = require('cors');
const crypto = require('crypto');
const admin = require('firebase-admin');

const app = express();
app.use(cors());
// On garde le corps brut (req.rawBody) en plus du JSON parsé : la vérification
// de signature du webhook Genius Pay porte sur les octets exacts envoyés, pas
// sur une version re-sérialisée par JSON.stringify (qui peut différer par
// l'ordre des clés ou les espaces).
app.use(express.json({
  verify: (req, res, buf) => {
    req.rawBody = buf;
  },
}));

const PORT = process.env.PORT || 3000; // Render will inject its own PORT
const ONESIGNAL_APP_ID = '38e7126f-2c23-4ee7-b715-6db2718ea78f';

// ---------------------------
// Firebase Admin -- nécessaire pour que le webhook puisse confirmer un
// paiement dans Firestore (users/orders/subscriptionPayments/notifications).
// Best-effort : si la clé de service n'est pas configurée, /payment continue
// de fonctionner normalement, seul le webhook est inopérant (avec un message
// d'erreur explicite dans les logs à chaque appel).
// ---------------------------
let db = null;
try {
  const serviceAccountJson = process.env.FIREBASE_SERVICE_ACCOUNT_JSON;
  if (serviceAccountJson) {
    const serviceAccount = JSON.parse(serviceAccountJson);
    admin.initializeApp({ credential: admin.credential.cert(serviceAccount) });
    db = admin.firestore();
    console.log('✅ Firebase Admin initialisé');
  } else {
    console.warn('⚠️ FIREBASE_SERVICE_ACCOUNT_JSON absent -- le webhook Genius Pay ne pourra pas confirmer les paiements dans Firestore.');
  }
} catch (e) {
  console.error('❌ Échec init Firebase Admin:', e.message);
}

// ---------------------------
// Helper: call Genius Pay API
// ---------------------------
async function createGeniusPayPayment(data) {
  const url = 'https://geniuspay.ci/api/v1/merchant/payments';
  const response = await fetch(url, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'X-API-Key': process.env.GENIUS_PAY_API_KEY,        // you will set this on Render
      'X-API-Secret': process.env.GENIUS_PAY_API_SECRET, // **protected** on Render
    },
    body: JSON.stringify(data),
  });

  if (!response.ok) {
    const err = await response.text();
    throw new Error(`Genius Pay error ${response.status}: ${err}`);
  }

  return response.json(); // contains checkout_url, reference, etc.
}

async function fetchGeniusPayTransaction(reference) {
  const url = `https://geniuspay.ci/api/v1/merchant/payments/${encodeURIComponent(reference)}`;
  const response = await fetch(url, {
    headers: {
      'X-API-Key': process.env.GENIUS_PAY_API_KEY,
      'X-API-Secret': process.env.GENIUS_PAY_API_SECRET,
    },
  });

  if (!response.ok) {
    const err = await response.text();
    throw new Error(`Genius Pay error ${response.status}: ${err}`);
  }

  return response.json();
}

async function notifySellerPush(sellerId, title, message, data) {
  const restApiKey = process.env.ONESIGNAL_REST_API_KEY;
  if (!restApiKey || !sellerId) return;
  try {
    await fetch('https://onesignal.com/api/v1/notifications', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json; charset=utf-8',
        'Authorization': `Basic ${restApiKey}`,
      },
      body: JSON.stringify({
        app_id: ONESIGNAL_APP_ID,
        target_channel: 'push',
        include_aliases: { external_id: [sellerId] },
        headings: { en: title, fr: title },
        contents: { en: message, fr: message },
        data: { type: 'order', ...data },
      }),
    });
  } catch (e) {
    console.error('⚠️ Push OneSignal échoué:', e.message);
  }
}

// Meme mecanisme que notifySellerPush, mais pour une LISTE de destinataires
// (les acheteurs abonnes a une boutique, cf. handleCampaignWebhook) --
// OneSignal accepte un tableau external_id, un seul appel suffit donc quel
// que soit le nombre d'abonnes.
async function notifyBuyersPush(buyerIds, title, message, data) {
  const restApiKey = process.env.ONESIGNAL_REST_API_KEY;
  if (!restApiKey || !buyerIds || buyerIds.length === 0) return;
  try {
    await fetch('https://onesignal.com/api/v1/notifications', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json; charset=utf-8',
        'Authorization': `Basic ${restApiKey}`,
      },
      body: JSON.stringify({
        app_id: ONESIGNAL_APP_ID,
        target_channel: 'push',
        include_aliases: { external_id: buyerIds },
        headings: { en: title, fr: title },
        contents: { en: message, fr: message },
        data: { type: 'store_update', updateType: 'campaign', ...data },
      }),
    });
  } catch (e) {
    console.error('⚠️ Push OneSignal (campagne) échoué:', e.message);
  }
}

// ---------------------------
// Public endpoint for your app
// ---------------------------
app.post('/payment', async (req, res) => {
  try {
    // Forward the request body directly (you may want validation in production)
    const geniusResponse = await createGeniusPayPayment(req.body);
    res.json(geniusResponse);
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: e.message });
  }
});

// ---------------------------
// Vérification manuelle d'une transaction (repli côté app si le webhook n'a
// pas encore confirmé -- voir genius_pay_service.dart::verifyTransaction).
// ---------------------------
app.get('/transaction/verify/:reference', async (req, res) => {
  try {
    const result = await fetchGeniusPayTransaction(req.params.reference);
    res.json(result);
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: e.message });
  }
});

// ---------------------------
// Webhook Genius Pay -- confirmation ASYNCHRONE de paiement.
//
// Avant ce webhook, l'app mobile considérait une commande/un abonnement comme
// payé dès l'OUVERTURE de la page de paiement Genius Pay (openCheckout), pas
// à la confirmation réelle -- un client qui annulait laissait une commande
// bloquée pour toujours, panier déjà vidé. Ce webhook devient la seule source
// de vérité pour "le paiement a réellement abouti".
//
// Contrat avec l'app (lib/services/genius_pay_service.dart) : le `metadata`
// envoyé à la création du paiement revient tel quel dans `data.metadata` du
// webhook. `metadata.paymentKind` distingue :
//   - 'subscription' (payment_screen.dart)  -> userId, planName, days,
//     subscriptionPaymentId
//   - 'order' (checkout_screen.dart)        -> orderId, buyerId, sellerId
// ---------------------------
function isSignatureValid(req) {
  const secret = process.env.GENIUS_PAY_WEBHOOK_SECRET;
  if (!secret || !req.rawBody) return false;

  const signature = req.get('X-Webhook-Signature');
  const timestamp = req.get('X-Webhook-Timestamp');
  if (!signature || !timestamp) return false;

  // Anti-rejeu : refuse un webhook de plus de 5 minutes.
  const ageSeconds = Math.abs(Date.now() / 1000 - Number(timestamp));
  if (!Number.isFinite(ageSeconds) || ageSeconds > 300) return false;

  const expected = crypto
    .createHmac('sha256', secret)
    .update(`${timestamp}.${req.rawBody}`)
    .digest('hex');

  const expectedBuf = Buffer.from(expected, 'utf8');
  const signatureBuf = Buffer.from(signature, 'utf8');
  if (expectedBuf.length !== signatureBuf.length) return false;
  return crypto.timingSafeEqual(expectedBuf, signatureBuf);
}

app.post('/webhook/genius-pay', async (req, res) => {
  if (!isSignatureValid(req)) {
    console.warn('🚨 Webhook Genius Pay rejeté : signature invalide ou absente');
    return res.status(401).json({ error: 'invalid signature' });
  }

  // On accuse réception tout de suite -- éviter que Genius Pay ne renvoie le
  // même webhook en boucle pendant qu'on écrit dans Firestore.
  res.status(200).json({ received: true });

  if (!db) {
    console.error(
      '❌ Webhook reçu mais Firebase Admin non configuré -- paiement NON confirmé dans Firestore. reference=',
      req.body?.data?.reference,
    );
    return;
  }

  try {
    const txData = req.body?.data || {};
    const status = txData.status;
    const metadata = txData.metadata || {};

    if (metadata.paymentKind === 'subscription') {
      await handleSubscriptionWebhook(status, metadata);
    } else if (metadata.paymentKind === 'order') {
      await handleOrderWebhook(status, metadata);
    } else if (metadata.paymentKind === 'campaign') {
      await handleCampaignWebhook(status, metadata);
    } else {
      console.warn('⚠️ Webhook Genius Pay avec metadata.paymentKind inconnu:', metadata);
    }
  } catch (e) {
    console.error('❌ Erreur traitement webhook Genius Pay:', e);
  }
});

async function handleSubscriptionWebhook(status, metadata) {
  const { userId, planName, days, subscriptionPaymentId } = metadata;
  if (!userId) {
    console.error('❌ Webhook abonnement sans userId dans metadata');
    return;
  }

  if (subscriptionPaymentId) {
    await db
      .collection('subscriptionPayments')
      .doc(subscriptionPaymentId)
      .update({
        paymentStatus: status === 'completed' ? 'completed' : status,
        lastUpdated: admin.firestore.FieldValue.serverTimestamp(),
      })
      .catch((e) => console.error('subscriptionPayments update failed:', e.message));
  }

  if (status !== 'completed') {
    console.log(`ℹ️ Paiement abonnement ${userId} : statut ${status}, aucun changement d'accès`);
    return;
  }

  const expiryDate = new Date(Date.now() + Number(days || 30) * 24 * 60 * 60 * 1000);
  await db.collection('users').doc(userId).update({
    isSubscribed: true,
    currentPlan: planName,
    subscriptionDate: admin.firestore.Timestamp.fromDate(expiryDate),
  });

  const storesSnap = await db
    .collection('stores')
    .where('ownerId', '==', userId)
    .limit(1)
    .get();
  if (!storesSnap.empty) {
    await storesSnap.docs[0].ref.update({ isActive: true });
  }

  console.log(`✅ Abonnement confirmé pour ${userId} (${planName})`);
}

async function handleOrderWebhook(status, metadata) {
  const { orderId, buyerId, sellerId } = metadata;
  if (!orderId) {
    console.error('❌ Webhook commande sans orderId dans metadata');
    return;
  }

  const orderRef = db.collection('orders').doc(orderId);
  const orderSnap = await orderRef.get();
  if (!orderSnap.exists) {
    console.error(`❌ Webhook commande introuvable: ${orderId}`);
    return;
  }
  const orderData = orderSnap.data();

  if (status === 'completed') {
    await orderRef.update({
      paymentStatus: 'completed',
      lastUpdated: admin.firestore.FieldValue.serverTimestamp(),
    });

    // Notifier le vendeur et vider le panier de l'acheteur -- déplacé ici
    // depuis le client (checkout_screen.dart), qui ne pouvait pas savoir si
    // le paiement avait réellement abouti après avoir simplement ouvert la
    // page de paiement Genius Pay.
    if (sellerId) {
      const title = 'Nouvelle commande';
      const message = `${orderData.buyerName || 'Un client'} a passé une commande de ${orderData.totalAmount} CFA`;
      await db.collection('notifications').add({
        receiverId: sellerId,
        type: 'order',
        isRead: false,
        title,
        message,
        timestamp: admin.firestore.FieldValue.serverTimestamp(),
        data: { orderId },
      });
      await notifySellerPush(sellerId, title, message, { amount: orderData.totalAmount });
    }

    if (buyerId) {
      const cartSnap = await db.collection('cart').where('buyerId', '==', buyerId).get();
      if (!cartSnap.empty) {
        const batch = db.batch();
        cartSnap.docs.forEach((doc) => batch.delete(doc.ref));
        await batch.commit();
      }
    }

    console.log(`✅ Commande ${orderId} confirmée payée`);
  } else if (['failed', 'cancelled', 'expired'].includes(status)) {
    // Le panier N'EST PAS vidé : le client garde ses articles et peut
    // réessayer le paiement.
    await orderRef.update({
      paymentStatus: 'checkout_failed',
      status: 'cancelled',
      lastUpdated: admin.firestore.FieldValue.serverTimestamp(),
    });
    console.log(`ℹ️ Commande ${orderId} : paiement ${status}, panier conservé pour réessai`);
  } else {
    console.log(`ℹ️ Commande ${orderId} : statut intermédiaire ${status}`);
  }
}

// Confirme le paiement d'une campagne marketing (create_campaign_screen.dart)
// et, pour les campagnes "In-App", pose la mise en avant sur les produits de
// la boutique -- cote serveur uniquement (Admin SDK, contourne les regles
// Firestore, qui interdisent desormais au vendeur d'ecrire lui-meme
// campaigns.status/paymentStatus ou products.featuredCampaignId/
// featuredPriority/featuredUntil). Avant ce webhook, ces champs etaient
// figes sur 'pending_payment' pour toujours (aucun paiement jamais debite),
// et la mise en avant etait appliquee IMMEDIATEMENT et GRATUITEMENT a la
// creation de la campagne, sans jamais lire la mise en avant nulle part
// cote acheteur -- fonctionnalite inerte des deux cotes (audit du
// 2026-09-02, corrige le 2026-09-05 une fois shop_screen.dart mis a jour
// pour trier reellement dessus).
async function handleCampaignWebhook(status, metadata) {
  const { campaignId } = metadata;
  if (!campaignId) {
    console.error('❌ Webhook campagne sans campaignId dans metadata');
    return;
  }

  const campaignRef = db.collection('campaigns').doc(campaignId);
  const campaignSnap = await campaignRef.get();
  if (!campaignSnap.exists) {
    console.error(`❌ Webhook campagne introuvable: ${campaignId}`);
    return;
  }
  const campaign = campaignSnap.data();

  if (status === 'completed') {
    // 'En cours' (et non 'active') pour matcher le statut deja attendu par
    // l'affichage existant dans marketing_screen.dart (rawStatus == 'En cours').
    await campaignRef.update({
      status: 'En cours',
      paymentStatus: 'completed',
      lastUpdated: admin.firestore.FieldValue.serverTimestamp(),
    });

    if (campaign.channel === 'inapp') {
      const duration = Number(campaign.duration) || 7;
      // Priorite proportionnelle au budget quotidien -- une campagne plus
      // genereuse ou plus courte doit ressortir davantage qu'une campagne
      // au budget etale sur une longue duree.
      const priority = Math.round((Number(campaign.budget) || 0) / duration);
      const until = admin.firestore.Timestamp.fromMillis(
        Date.now() + duration * 24 * 60 * 60 * 1000
      );

      const productsSnap = await db
        .collection('products')
        .where('storeId', '==', campaign.storeId)
        .get();
      if (!productsSnap.empty) {
        const batch = db.batch();
        productsSnap.docs.forEach((doc) => {
          batch.update(doc.ref, {
            featuredCampaignId: campaignId,
            featuredPriority: priority,
            featuredUntil: until,
          });
        });
        await batch.commit();
      }
    } else if (campaign.channel === 'push') {
      // Envoie reellement la campagne "push" aux acheteurs abonnes a cette
      // boutique (store_subscriptions) -- avant ce webhook, une campagne
      // 'push' etait creee/facturee mais rien ne l'envoyait jamais nulle
      // part (audit du 2026-09-06). Le texte utilise est celui choisi/genere
      // par le vendeur a la creation (campaign.aiText), avec un repli
      // generique s'il ne l'a pas rempli.
      const subsSnap = await db
        .collection('store_subscriptions')
        .where('storeId', '==', campaign.storeId)
        .get();
      const buyerIds = subsSnap.docs
        .map((doc) => doc.data().buyerId)
        .filter((id) => typeof id === 'string' && id.length > 0);

      if (buyerIds.length > 0) {
        const message =
          campaign.aiText && campaign.aiText.trim().length > 0
            ? campaign.aiText
            : `${campaign.name} : decouvrez nos offres !`;
        await notifyBuyersPush(buyerIds, campaign.name || 'Nouvelle offre', message, {
          storeId: campaign.storeId,
          campaignId,
        });
      }
    }

    console.log(`✅ Campagne ${campaignId} confirmee payee`);
  } else if (['failed', 'cancelled', 'expired'].includes(status)) {
    await campaignRef.update({
      status: 'checkout_failed',
      paymentStatus: 'checkout_failed',
      lastUpdated: admin.firestore.FieldValue.serverTimestamp(),
    });
    console.log(`ℹ️ Campagne ${campaignId} : paiement ${status}`);
  } else {
    console.log(`ℹ️ Campagne ${campaignId} : statut intermediaire ${status}`);
  }
}

// ---------------------------
// Verifie le token Firebase envoye par le client (header Authorization:
// Bearer <idToken>). Renvoie le uid decode, ou lance si absent/invalide.
// ---------------------------
async function requireAuth(req) {
  const header = req.get('Authorization') || '';
  const idToken = header.startsWith('Bearer ') ? header.slice(7) : '';
  if (!idToken) {
    const err = new Error('missing auth token');
    err.statusCode = 401;
    throw err;
  }
  try {
    return await admin.auth().verifyIdToken(idToken);
  } catch (e) {
    const err = new Error('invalid auth token');
    err.statusCode = 401;
    throw err;
  }
}

// ---------------------------
// Confirmation manuelle d'un paiement -- repli cote app quand l'utilisateur
// revient dans l'app avant que le webhook Genius Pay n'ait eu le temps
// d'arriver (voir /transaction/verify/:reference plus haut, qui ne fait
// qu'AFFICHER le statut sans jamais rien ecrire). Reutilise exactement la
// meme logique que le webhook (handleOrderWebhook/handleSubscriptionWebhook),
// simplement declenchee par le client plutot que par Genius Pay -- protegee
// par une verification d'identite Firebase + un controle de propriete du
// paiement, pour qu'un utilisateur ne puisse jamais confirmer le paiement de
// quelqu'un d'autre. Le statut confirme reste celui reellement renvoye par
// Genius Pay (fetchGeniusPayTransaction), jamais celui envoye par le client.
//
// Audit du 2026-09-05 : avant ce endpoint, l'app mobile ecrivait elle-meme
// paymentStatus/isSubscribed directement dans Firestore apres avoir appele
// /transaction/verify -- rien n'empechait un client de sauter cette
// verification et d'ecrire directement un statut "paye" bidon.
app.post('/transaction/confirm/:reference', async (req, res) => {
  try {
    const decoded = await requireAuth(req);

    const result = await fetchGeniusPayTransaction(req.params.reference);
    const txData = result.data || result;
    const status = txData.status;
    const metadata = txData.metadata || {};

    if (metadata.paymentKind === 'subscription') {
      if (metadata.userId !== decoded.uid) {
        return res.status(403).json({ error: 'not your payment' });
      }
      if (!db) return res.status(503).json({ error: 'firestore not configured' });
      await handleSubscriptionWebhook(status, metadata);
    } else if (metadata.paymentKind === 'order') {
      if (metadata.buyerId !== decoded.uid) {
        return res.status(403).json({ error: 'not your payment' });
      }
      if (!db) return res.status(503).json({ error: 'firestore not configured' });
      await handleOrderWebhook(status, metadata);
    } else if (metadata.paymentKind === 'campaign') {
      if (metadata.ownerId !== decoded.uid) {
        return res.status(403).json({ error: 'not your payment' });
      }
      if (!db) return res.status(503).json({ error: 'firestore not configured' });
      await handleCampaignWebhook(status, metadata);
    } else {
      return res.status(400).json({ error: 'unknown paymentKind in metadata' });
    }

    res.json({ status });
  } catch (e) {
    console.error(e);
    res.status(e.statusCode || 500).json({ error: e.message });
  }
});

// ---------------------------
// Liberation du sequestre par code PIN -- avant ce endpoint, le client
// (escrow_service.dart) ecrivait directement escrow.status/orders.escrowStatus
// dans Firestore, et la regle Firestore permettait a n'importe quelle partie
// du sequestre (acheteur inclus) de le faire sans jamais entrer le bon PIN ni
// meme avoir paye (audit du 2026-09-05). Le PIN et l'etat de paiement sont
// desormais verifies ici, cote serveur, avant toute ecriture.
// ---------------------------
app.post('/escrow/release', async (req, res) => {
  try {
    const decoded = await requireAuth(req);
    if (!db) return res.status(503).json({ error: 'firestore not configured' });

    const { orderId, pin } = req.body || {};
    if (!orderId || !pin) {
      return res.status(400).json({ error: 'orderId and pin required' });
    }

    const orderRef = db.collection('orders').doc(orderId);
    const orderSnap = await orderRef.get();
    if (!orderSnap.exists) {
      return res.status(404).json({ error: 'order not found' });
    }
    const order = orderSnap.data();

    const uid = decoded.uid;
    const isAuthorized =
      order.sellerId === uid ||
      order.assignedDriverId === uid ||
      order.livreurId === uid ||
      order.driverId === uid;
    if (!isAuthorized) {
      return res.status(403).json({ error: 'not authorized for this order' });
    }

    if (order.escrowStatus !== 'in_escrow') {
      return res.status(409).json({ error: 'order not in escrow' });
    }

    const paidStatuses = ['pay_on_delivery', 'test_mode_paid', 'completed'];
    if (!paidStatuses.includes(order.paymentStatus)) {
      return res.status(409).json({ error: 'payment not confirmed' });
    }

    if (!order.customerPin || order.customerPin !== pin) {
      return res.json({ success: false });
    }

    const escrowId = order.escrowId;
    if (!escrowId) {
      return res.status(409).json({ error: 'escrow not found for this order' });
    }

    const now = admin.firestore.FieldValue.serverTimestamp();
    const batch = db.batch();
    batch.update(db.collection('escrow').doc(escrowId), {
      status: 'released',
      pinValidatedAt: now,
      releasedAt: now,
    });
    batch.update(orderRef, {
      escrowStatus: 'released',
      status: 'delivered',
      deliveryStatus: 'delivered',
      escrowReleasedAt: now,
      lastUpdated: now,
    });
    await batch.commit();

    res.json({ success: true });
  } catch (e) {
    console.error(e);
    res.status(e.statusCode || 500).json({ error: e.message });
  }
});

// ---------------------------
// Octroi gratuit en mode test -- PAYMENTS_DISABLED est ici une variable
// d'environnement DU SERVEUR (Render), pas du client : contrairement au flag
// cote app (lib/services/payment_config.dart, extrait facilement d'un APK),
// celle-ci ne peut pas etre falsifiee par le client. Sans ce endpoint, une
// commande/un abonnement cree en mode test restait bloque a
// 'awaiting_checkout' pour toujours, puisque le client ne peut plus ecrire
// paymentStatus lui-meme (regles Firestore, audit du 2026-09-05).
// ---------------------------
app.post('/payment/grant-test-mode', async (req, res) => {
  try {
    const decoded = await requireAuth(req);
    if (process.env.PAYMENTS_DISABLED !== 'true') {
      return res.status(403).json({ error: 'test mode not enabled on server' });
    }
    if (!db) return res.status(503).json({ error: 'firestore not configured' });

    const body = req.body || {};
    const paymentKind = body.paymentKind;

    if (paymentKind === 'subscription') {
      const { userId, planName, days, subscriptionPaymentId } = body;
      if (userId !== decoded.uid) {
        return res.status(403).json({ error: 'not your payment' });
      }
      await handleSubscriptionWebhook('completed', {
        userId,
        planName,
        days,
        subscriptionPaymentId,
      });
    } else if (paymentKind === 'order') {
      const { orderId, buyerId, sellerId } = body;
      if (buyerId !== decoded.uid) {
        return res.status(403).json({ error: 'not your payment' });
      }
      await handleOrderWebhook('completed', { orderId, buyerId, sellerId });
    } else if (paymentKind === 'campaign') {
      const { campaignId, ownerId } = body;
      if (ownerId !== decoded.uid) {
        return res.status(403).json({ error: 'not your payment' });
      }
      await handleCampaignWebhook('completed', { campaignId, ownerId });
    } else {
      return res.status(400).json({ error: 'unknown paymentKind' });
    }

    res.json({ status: 'completed' });
  } catch (e) {
    console.error(e);
    res.status(e.statusCode || 500).json({ error: e.message });
  }
});

app.get('/', (req, res) => {
  res.send('W‑Com Genius Pay backend is running');
});

app.listen(PORT, () => {
  console.log(`🚀 Server listening on port ${PORT}`);
});
