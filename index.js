// index.js
require('dotenv').config();          // loads .env locally (development only)

const express = require('express');
const cors = require('cors');
const crypto = require('crypto');
const cron = require('node-cron');
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
//   - 'driver_subscription' (livreur_subscription_screen.dart) -> userId,
//     days, subscriptionPaymentId (même schéma que 'subscription', mais
//     écrit sur public_drivers/{userId} au lieu de users/{userId} -- un
//     compte peut être vendeur ET livreur en même temps, les deux
//     abonnements doivent rester indépendants)
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
    } else if (metadata.paymentKind === 'driver_subscription') {
      await handleDriverSubscriptionWebhook(status, metadata);
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

  // Renouvellement anticipé : si l'abonnement en cours n'est pas encore
  // expiré, les nouveaux jours s'ajoutent à sa date d'expiration au lieu de
  // repartir de maintenant -- sinon un vendeur qui renouvelle quelques jours
  // avant l'échéance perdait les jours restants déjà payés (signalé
  // 2026-09-08, KPI Abonnement).
  const now = Date.now();
  let baseTime = now;
  try {
    const userSnap = await db.collection('users').doc(userId).get();
    const existingExpiry = userSnap.data()?.subscriptionDate;
    if (existingExpiry && existingExpiry.toDate().getTime() > now) {
      baseTime = existingExpiry.toDate().getTime();
    }
  } catch (e) {
    console.error('Lecture subscriptionDate existante échouée, base = maintenant:', e.message);
  }

  const expiryDate = new Date(baseTime + Number(days || 30) * 24 * 60 * 60 * 1000);
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

  console.log(`✅ Abonnement confirmé pour ${userId} (${planName}), expire le ${expiryDate.toISOString()}`);
}

// Miroir de handleSubscriptionWebhook pour l'abonnement livreur (2 500
// FCFA/mois, livreur_subscription_screen.dart) -- même logique, mais écrit
// sur public_drivers/{userId} (subscriptionActive/subscriptionExpiresAt) au
// lieu de users/{userId} (isSubscribed/currentPlan), et n'active aucune
// boutique. Sans ce handler, firestore.rules::public_drivers empêche le
// client d'écrire ces champs lui-même (audit du 2026-09-04, même faille que
// users/{userId}.isSubscribed) : le paiement resterait indéfiniment à
// 'awaiting_checkout'.
async function handleDriverSubscriptionWebhook(status, metadata) {
  const { userId, days, subscriptionPaymentId } = metadata;
  if (!userId) {
    console.error('❌ Webhook abonnement livreur sans userId dans metadata');
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
    console.log(`ℹ️ Paiement abonnement livreur ${userId} : statut ${status}, aucun changement d'accès`);
    return;
  }

  // Même correctif que handleSubscriptionWebhook ci-dessus (2026-09-08) :
  // cumule sur la date d'expiration existante si elle n'est pas encore
  // passée, au lieu d'écraser les jours restants déjà payés.
  const now = Date.now();
  let baseTime = now;
  try {
    const driverSnap = await db.collection('public_drivers').doc(userId).get();
    const existingExpiry = driverSnap.data()?.subscriptionExpiresAt;
    if (existingExpiry && existingExpiry.toDate().getTime() > now) {
      baseTime = existingExpiry.toDate().getTime();
    }
  } catch (e) {
    console.error('Lecture subscriptionExpiresAt existante échouée, base = maintenant:', e.message);
  }

  const expiryDate = new Date(baseTime + Number(days || 30) * 24 * 60 * 60 * 1000);
  await db.collection('public_drivers').doc(userId).update({
    subscriptionActive: true,
    subscriptionExpiresAt: admin.firestore.Timestamp.fromDate(expiryDate),
  });

  console.log(`✅ Abonnement livreur confirmé pour ${userId}, expire le ${expiryDate.toISOString()}`);
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
    // BUG (signale par l'utilisateur 2026-09-05, corrige) : seul paymentStatus
    // passait a 'completed' ici -- orders.status restait bloque sur
    // 'awaiting_payment' (sa valeur de creation) jusqu'a ce que le vendeur
    // clique manuellement "Expedier" ou que le PIN de livraison soit valide.
    // Une commande reellement payee s'affichait donc indefiniment comme "en
    // attente de paiement" cote vendeur. 'pending' est le statut suivant
    // attendu par le client (orders_screen.dart::_statusLabel).
    await orderRef.update({
      paymentStatus: 'completed',
      status: 'pending',
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
    } else if (metadata.paymentKind === 'driver_subscription') {
      if (metadata.userId !== decoded.uid) {
        return res.status(403).json({ error: 'not your payment' });
      }
      if (!db) return res.status(503).json({ error: 'firestore not configured' });
      await handleDriverSubscriptionWebhook(status, metadata);
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
// Confirmation gratuite d'une campagne 'whatsapp' -- ce canal n'a aucun
// envoi automatise reel (aucun compte WhatsApp Business API/Meta configure
// dans ce projet) : facturer le budget affiche pour un canal qui ne
// delivre rien serait trompeur, donc il reste gratuit tant qu'aucune vraie
// integration n'existe (decision produit du 2026-09-06). Le canal est
// RE-VERIFIE ici a partir du document Firestore reel, jamais depuis une
// valeur envoyee par le client -- un vendeur ne peut donc pas se faire
// accorder gratuitement une campagne 'inapp'/'push' en pretendant qu'elle
// est 'whatsapp'.
// ---------------------------
app.post('/campaign/confirm-free', async (req, res) => {
  try {
    const decoded = await requireAuth(req);
    if (!db) return res.status(503).json({ error: 'firestore not configured' });

    const { campaignId } = req.body || {};
    if (!campaignId) {
      return res.status(400).json({ error: 'campaignId required' });
    }

    const campaignRef = db.collection('campaigns').doc(campaignId);
    const campaignSnap = await campaignRef.get();
    if (!campaignSnap.exists) {
      return res.status(404).json({ error: 'campaign not found' });
    }
    const campaign = campaignSnap.data();

    if (campaign.channel !== 'whatsapp') {
      return res.status(403).json({ error: 'only whatsapp campaigns are free' });
    }

    const storeSnap = await db.collection('stores').doc(campaign.storeId).get();
    if (!storeSnap.exists || storeSnap.data().ownerId !== decoded.uid) {
      return res.status(403).json({ error: 'not your campaign' });
    }

    await handleCampaignWebhook('completed', { campaignId });
    res.json({ status: 'completed' });
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
    let isAuthorized =
      order.sellerId === uid ||
      order.livreurId === uid ||
      order.driverId === uid;

    // BUG (signale par l'utilisateur 2026-09-05, corrige) : order.assignedDriverId
    // est l'ID du document delivery_drivers (l'entree de flotte cote vendeur,
    // cree via .add() dans le client), jamais egal a l'UID Firebase Auth reel
    // du livreur -- cette comparaison directe ne pouvait donc jamais passer
    // pour le livreur, qui se voyait rejete en permanence ("PIN incorrect")
    // meme avec le bon code, l'obligeant a demander au vendeur de valider a
    // sa place. On resout le vrai UID via le champ userId du document
    // delivery_drivers correspondant (present pour un livreur "public",
    // absent pour un livreur ajoute manuellement -- qui n'a de toute facon
    // pas de compte pour appeler ce endpoint).
    if (!isAuthorized && order.assignedDriverId) {
      const fleetEntrySnap = await db
        .collection('delivery_drivers')
        .doc(order.assignedDriverId)
        .get();
      const fleetEntryUserId = fleetEntrySnap.exists
        ? fleetEntrySnap.data().userId
        : null;
      isAuthorized = fleetEntryUserId === uid;
    }

    if (!isAuthorized) {
      return res.status(403).json({ error: 'not authorized for this order' });
    }

    if (order.escrowStatus !== 'in_escrow') {
      // Idempotence : si la commande est déjà marquée livrée ou l'escrow déjà libéré,
      // et que le PIN concorde (ou si le PIN avait déjà été validé), on retourne
      // un succès immédiat pour éviter l'erreur 409 lors d'une nouvelle tentative.
      if (order.escrowStatus === 'released' || order.status === 'delivered') {
        if (!order.customerPin || order.customerPin === pin) {
          return res.json({ success: true, alreadyReleased: true });
        }
      }
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
    } else if (paymentKind === 'driver_subscription') {
      const { userId, days, subscriptionPaymentId } = body;
      if (userId !== decoded.uid) {
        return res.status(403).json({ error: 'not your payment' });
      }
      await handleDriverSubscriptionWebhook('completed', {
        userId,
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

// ---------------------------
// Demande de retrait -- recalcule le solde reellement disponible cote
// serveur (Admin SDK) avant d'ecrire quoi que ce soit dans withdrawals
// (signale par l'utilisateur 2026-09-05) : portefeuille_screen.dart
// ecrivait auparavant directement dans Firestore, et la regle ne
// verifiait que l'identite du vendeur, jamais que le montant demande
// correspondait a un solde reel -- n'importe quel client pouvait donc
// demander un retrait pour un montant arbitraire. Reprend exactement la
// meme logique de calcul que portefeuille_screen.dart (statuts payes,
// escrowReleasedAt, delai de 24h) pour ne jamais rejeter un retrait
// legitime que l'ecran affiche pourtant comme disponible.
// ---------------------------
const PAID_ORDER_STATUSES = new Set(['pay_on_delivery', 'test_mode_paid', 'completed']);

async function computeAvailableBalance(sellerId) {
  const [ordersSnap, withdrawalsSnap, vaultsSnap] = await Promise.all([
    db.collection('orders').where('sellerId', '==', sellerId).get(),
    db.collection('withdrawals').where('sellerId', '==', sellerId).get(),
    db.collection('vaults').where('sellerId', '==', sellerId).get(),
  ]);

  const now = new Date();
  let availableBalance = 0;

  ordersSnap.forEach((doc) => {
    const data = doc.data();
    const amount = Number(data.sellerAmount ?? data.totalAmount ?? 0);
    const status = data.status || 'pending';
    const paymentStatus = data.paymentStatus;
    const escrowStatus = (data.escrowStatus || 'none').toString();

    if (
      (status === 'delivered' || status === 'shipped') &&
      !PAID_ORDER_STATUSES.has(paymentStatus)
    ) {
      return;
    }
    if (status !== 'delivered' || escrowStatus === 'in_escrow') {
      return;
    }

    const releaseDate =
      (data.escrowReleasedAt && data.escrowReleasedAt.toDate && data.escrowReleasedAt.toDate()) ||
      (data.timestamp && data.timestamp.toDate && data.timestamp.toDate());
    if (releaseDate && (now - releaseDate) / 3600000 >= 24) {
      availableBalance += amount;
    }
  });

  let totalWithdrawn = 0;
  withdrawalsSnap.forEach((doc) => {
    const data = doc.data();
    const amount = Number(data.amount || 0);
    const status = data.status || 'pending';
    if (status === 'completed' || status === 'pending') {
      totalWithdrawn += amount;
    }
  });

  // Les tirelires reservent reellement une partie du solde (audit du
  // 2026-09-05) : avant, une tirelire creditee par l'auto-epargne
  // (VaultService.processAutoSave, cote client) ne deduisait jamais rien
  // ici -- le vendeur pouvait donc retirer 100% d'une vente en plus de ce
  // que l'app lui affichait comme "mis de cote" dans sa tirelire, le meme
  // argent etant compte deux fois.
  let totalInVaults = 0;
  vaultsSnap.forEach((doc) => {
    totalInVaults += Number(doc.data().currentAmount || 0);
  });

  return availableBalance - totalWithdrawn - totalInVaults;
}

app.post('/withdrawal/request', async (req, res) => {
  try {
    const decoded = await requireAuth(req);
    if (!db) return res.status(503).json({ error: 'firestore not configured' });

    const { amount, method, accountNumber } = req.body || {};
    const requestedAmount = Number(amount);
    if (!Number.isFinite(requestedAmount) || requestedAmount <= 0) {
      return res.status(400).json({ error: 'invalid amount' });
    }

    const sellerId = decoded.uid;
    const availableBalance = await computeAvailableBalance(sellerId);

    if (requestedAmount > availableBalance) {
      return res
        .status(409)
        .json({ error: 'amount exceeds available balance', availableBalance });
    }

    const ref = await db.collection('withdrawals').add({
      sellerId,
      amount: requestedAmount,
      status: 'pending',
      method: method || null,
      accountNumber: accountNumber || null,
      createdAt: admin.firestore.FieldValue.serverTimestamp(),
    });

    res.json({ success: true, withdrawalId: ref.id });
  } catch (e) {
    console.error(e);
    res.status(e.statusCode || 500).json({ error: e.message });
  }
});

// ---------------------------
// Conseils IA du tableau de bord Statistiques -- avant, statistics_screen.dart
// appelait directement l'API NVIDIA depuis le client avec la cle
// NVIDIA_API_KEY embarquee dans le .env de l'app (donc extractible d'un APK),
// permettant a n'importe qui de consommer/facturer le quota NVIDIA du compte
// W-Com sans jamais passer par l'app (audit du 2026-09-05). Le prompt et
// l'appel NVIDIA sont desormais construits ici, la cle ne quitte plus le
// serveur ; le client envoie uniquement les metriques deja calculees
// localement (rien de sensible) et recoit le tableau d'insights deja parse.
// ---------------------------
app.post('/ai/insights', async (req, res) => {
  try {
    await requireAuth(req);

    const {
      grossRevenue,
      orderCount,
      storeRating,
      fidelity,
      totalItemsSold,
      topCategoryName,
      topCategoryCount,
      acquisition,
      outputLanguage,
    } = req.body || {};

    const lang = ['anglais', 'espagnol'].includes(outputLanguage)
      ? outputLanguage
      : 'français';
    const avgOrder = orderCount ? Number(grossRevenue) / Number(orderCount) : 0;

    const systemPrompt = `Tu es un conseiller commercial expert pour les vendeurs sur W-Com (une plateforme e-commerce africaine). Tu dois analyser les données du vendeur et donner 3 à 5 conseils concrets, pratiques et personnalisés.

Règles de formatage obligatoires :
- Réponds **uniquement** en JSON, pas de texte en dehors
- Le JSON doit être un tableau d'objets avec ces champs :
  - "title" (chaîne de caractères, court, en ${lang})
  - "desc" (chaîne de caractères, 1 à 2 phrases max, en ${lang})
  - "color" (chaîne de caractères : "orange", "cyan", "yellow", "green", "purple", "red")
  - "icon" (chaîne de caractères, nom d'icône Material Icons : lightbulb, warning, map, shopping_cart, star, attach_money, etc.)

Exemple de réponse valide :
[
  {"title": "Augmentez votre panier moyen", "desc": "Votre panier moyen est bas. Proposez des packs produits.", "color": "cyan", "icon": "shopping_cart"},
  {"title": "Fidélisez vos clients", "desc": "Votre taux de fidélité est faible. Créez un programme de récompenses.", "color": "orange", "icon": "favorite"}
]`;

    const userPrompt = `Voici les données du vendeur :
- Chiffre d'affaires total (période sélectionnée) : ${Number(grossRevenue || 0).toFixed(0)} FCFA
- Nombre de commandes : ${Number(orderCount || 0)}
- Panier moyen : ${avgOrder.toFixed(0)} FCFA
- Note moyenne de la boutique : ${storeRating || 0}/5
- Taux de fidélité (clients qui ont acheté plusieurs fois) : ${Number(fidelity || 0).toFixed(0)}%
- Nombre d'articles vendus : ${Number(totalItemsSold || 0)}
- Catégorie la plus vendue : ${topCategoryName || ''} (${Number(topCategoryCount || 0)} articles)
- Nombre de clients acquis (normalisé) : ${Number(acquisition || 0).toFixed(0)}%

Donne 3 à 5 conseils personnalisés pour améliorer les ventes.`;

    const nvidiaResponse = await fetch(
      'https://integrate.api.nvidia.com/v1/chat/completions',
      {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json; charset=utf-8',
          Authorization: `Bearer ${process.env.NVIDIA_API_KEY}`,
        },
        body: JSON.stringify({
          model: 'meta/llama-3.2-90b-vision-instruct',
          messages: [
            { role: 'system', content: systemPrompt },
            { role: 'user', content: userPrompt },
          ],
          max_tokens: 800,
          temperature: 0.7,
        }),
      }
    );

    if (!nvidiaResponse.ok) {
      return res.status(502).json({ error: 'ai upstream error' });
    }

    const responseData = await nvidiaResponse.json();
    const replyText = (responseData.choices?.[0]?.message?.content || '').trim();
    const jsonStart = replyText.indexOf('[');
    const jsonEnd = replyText.lastIndexOf(']') + 1;
    if (jsonStart === -1 || jsonEnd <= jsonStart) {
      return res.status(502).json({ error: 'invalid ai response' });
    }

    const insights = JSON.parse(replyText.substring(jsonStart, jsonEnd));
    res.json({ insights });
  } catch (e) {
    console.error(e);
    res.status(e.statusCode || 500).json({ error: e.message });
  }
});

// ---------------------------
// Proxy generique vers NVIDIA (chat/completions) -- meme faille que
// /ai/insights ci-dessus mais pour les autres fonctionnalites IA de l'app
// (chat Repos, generation de legendes, description produit, resume de
// conversation Workspace...) qui appelaient toutes NVIDIA directement
// depuis le client avec la cle embarquee (NVIDIA_API_KEY et/ou
// NVIDIA_VISION_API_KEY selon l'ecran, audit du 2026-09-06). Le client
// garde la construction de ses prompts (logique produit, pas sensible) ;
// seule la cle ne quitte plus jamais le serveur. Authentification Firebase
// requise (comme /ai/insights) -- n'empeche pas un utilisateur connecte
// d'utiliser un peu plus de quota que prevu, mais ferme l'exposition
// totale et anonyme de la cle. model restreint aux deux modeles reellement
// utilises par l'app, max_tokens plafonne, pour eviter qu'un appel
// detourne (mauvais modele, max_tokens enorme) ne coute plus que prevu.
// ---------------------------
const ALLOWED_AI_MODELS = new Set([
  'meta/llama-3.2-90b-vision-instruct',
  'meta/llama-3.2-11b-vision-instruct',
]);

const reposRateLimits = new Map();

// ==========================================
// PHASE 1F.10.3 : REPOS ASSISTANT ENDPOINT
// ==========================================
app.post('/ai/repos-assistant', async (req, res) => {
  try {
    const decoded = await requireAuth(req);
    const uid = decoded.uid;

    const now = Date.now();
    const userLimit = reposRateLimits.get(uid) || { count: 0, windowStart: now };
    if (now - userLimit.windowStart > 60000) {
      userLimit.count = 1;
      userLimit.windowStart = now;
    } else {
      userLimit.count++;
      if (userLimit.count > 15) {
        return res.status(429).json({
          error: 'rate_limit_exceeded',
          message: 'Too many AI requests. Please try again later.'
        });
      }
    }
    reposRateLimits.set(uid, userLimit);

    const { storeId, message, history, image, language = 'French' } = req.body || {};
    if (!storeId || typeof storeId !== 'string') return res.status(400).json({ error: 'storeId required' });
    if (!message || typeof message !== 'string') return res.status(400).json({ error: 'message required' });
    
    let safeHistory = [];
    if (Array.isArray(history)) {
      safeHistory = history
        .filter(h => h.role === 'user' || h.role === 'assistant')
        .slice(-8); // keep last 8
    }

    const storeSnap = await db.collection('stores').doc(storeId).get();
    if (!storeSnap.exists) {
      return res.status(403).json({ error: 'store not found' });
    }
    const storeData = storeSnap.data();
    if (storeData.ownerId !== uid) {
      return res.status(403).json({ error: 'access denied' });
    }

    const jsNow = new Date();
    const thirtyDaysAgoDate = new Date(jsNow);
    thirtyDaysAgoDate.setDate(jsNow.getDate() - 30);
    
    const sixtyDaysAgoDate = new Date(jsNow);
    sixtyDaysAgoDate.setDate(jsNow.getDate() - 60);

    const yesterdayDate = new Date(jsNow);
    yesterdayDate.setDate(jsNow.getDate() - 1);

    const [ordersSnap, productsSnap, reviewsSnap, driversSnap, driversBySellerSnap] = await Promise.all([
      db.collection('orders').where('sellerId', '==', uid).get(),
      db.collection('products').where('storeId', '==', storeId).get(),
      db.collection('product_reviews').where('storeId', '==', storeId).limit(5).get(),
      db.collection('delivery_drivers').where('storeId', '==', storeId).get(),
      db.collection('delivery_drivers').where('sellerId', '==', uid).get()
    ]);

    let totalRevenue = 0;
    let totalOrders = 0;
    let yesterdayRevenue = 0;
    let urgentOrders = 0;
    const productStats = {}; 
    const salesLast30DaysByName = {};
    const lastPurchaseMap = {};

    const ordersSortedDesc = [...ordersSnap.docs].sort((a,b) => {
      const ta = (a.data().timestamp?.toDate() || new Date(0)).getTime();
      const tb = (b.data().timestamp?.toDate() || new Date(0)).getTime();
      return tb - ta;
    });
    const recentOrdersDocs = ordersSortedDesc.slice(0, 10);

    for (const doc of ordersSnap.docs) {
      const data = doc.data();
      const ts = data.timestamp ? data.timestamp.toDate() : null;
      const buyerId = data.buyerId;

      if (buyerId && ts) {
        if (!lastPurchaseMap[buyerId] || ts > lastPurchaseMap[buyerId]) {
          lastPurchaseMap[buyerId] = ts;
        }
      }

      if (ts && ts > thirtyDaysAgoDate) {
        totalOrders++;
        totalRevenue += Number(data.totalAmount) || 0.0;

        const items = data.items || [];
        for (const item of items) {
          const name = item.name || 'Inconnu';
          const qty = Number(item.quantity) || 1;
          const price = Number(item.price) || 0.0;

          if (!productStats[name]) productStats[name] = { sales: 0, revenue: 0.0 };
          productStats[name].sales += qty;
          productStats[name].revenue += (price * qty);

          salesLast30DaysByName[name] = (salesLast30DaysByName[name] || 0) + qty;
        }
      }

      if (ts && ts.getFullYear() === yesterdayDate.getFullYear() && ts.getMonth() === yesterdayDate.getMonth() && ts.getDate() === yesterdayDate.getDate()) {
        yesterdayRevenue += Number(data.totalAmount) || 0.0;
      }
      if (data.status === 'pending') {
        urgentOrders++;
      }
    }

    let inactiveClientsCount = 0;
    for (const buyerId in lastPurchaseMap) {
      if (lastPurchaseMap[buyerId] < sixtyDaysAgoDate) {
        inactiveClientsCount++;
      }
    }

    const detailedProducts = [];
    const stockAlerts = [];
    const smartPricing = [];

    for (const doc of productsSnap.docs) {
      const data = doc.data();
      const name = data.name || 'Sans nom';
      const price = Number(data.price) || 0.0;
      const stock = Number(data.quantity) || 0;
      const createdAt = data.createdAt ? data.createdAt.toDate() : null;
      const salesLast30Days = salesLast30DaysByName[name] || 0;

      const stats = productStats[name] || { sales: 0, revenue: 0.0 };
      detailedProducts.push({
        id: doc.id,
        nom: name,
        prix: price,
        stock_actuel: stock,
        ventes_30j: stats.sales,
        ca_30j: stats.revenue,
      });

      const velocity = salesLast30Days / 30;
      if (velocity > 0) {
        const daysRemaining = Math.floor(stock / velocity);
        if (daysRemaining <= 5) {
          stockAlerts.push({
            productName: name,
            daysRemaining,
            stock,
            velocity: velocity.toFixed(1)
          });
        }
      }

      if (salesLast30Days === 0) {
        if (createdAt && (jsNow.getTime() - createdAt.getTime()) / (1000 * 3600 * 24) > 30) {
          smartPricing.push({
            productId: doc.id,
            productName: name,
            reason: 'Stock dormant (aucune vente depuis 30 jours)',
            suggestion: 'Créer une promotion ciblée (-15%)'
          });
        }
      } else if (salesLast30Days >= 10) {
        smartPricing.push({
          productId: doc.id,
          productName: name,
          reason: `Produit très demandé (${salesLast30Days} ventes ces 30 derniers jours)`,
          suggestion: 'Augmenter légèrement le prix (+5%)'
        });
      }
    }

    const recentReviews = reviewsSnap.docs.map(doc => `- ${doc.data().rating}/5: ${doc.data().comment || 'Pas de commentaire'}`).join("\n") || "Aucun avis";
    
    const recentOrders = recentOrdersDocs.map(doc => {
      const data = doc.data();
      return `- Commande ID=${doc.id}, Client=${data.customerName || 'Inconnu'}, Total=${Number(data.totalAmount)||0} CFA, Statut=${data.status||'pending'}, Livreur=${data.livreurName||'Non assigné'}`;
    }).join("\n");

    const actualDrivers = driversSnap.empty ? driversBySellerSnap.docs : driversSnap.docs;
    const availableDrivers = actualDrivers.map(doc => {
      const data = doc.data();
      return `- ${data.name || 'Inconnu'} : ID=${doc.id}, Statut=${data.driverStatus || 'disponible'}, Zones=${data.coverageCommunes || []}`;
    }).join("\n");

    const storeContext = `CONTEXTE BOUTIQUE :
- Nom : ${storeData.storeName || 'Ma Boutique'}
- Catégorie : ${storeData.category || 'Général'}
- Ville : ${storeData.commune || 'Non spécifiée'}
- Note : ${Number(storeData.averageRating)||0}/5 (${Number(storeData.reviewCount)||0} avis)

PERFORMANCES GLOBALES (30 JOURS) :
- CA Total : ${totalRevenue.toFixed(0)} CFA
- Commandes : ${totalOrders}

CATALOGUE DÉTAILLÉ (Prix, Stocks et Ventes) :
${detailedProducts.map(p => `- ${p.nom} : ID=${p.id}, Prix=${p.prix} CFA, Stock=${p.stock_actuel}, Ventes=${p.ventes_30j}, CA=${p.ca_30j} CFA`).join("\n")}

COMMANDES RÉCENTES (10 dernières) :
${recentOrders}

LISTE DES LIVREURS :
${availableDrivers}

AVIS RÉCENTS :
${recentReviews}`;

    const insightsText = JSON.stringify({
      stockAlerts,
      smartPricing,
      dailyBriefing: { yesterdayRevenue, urgentOrders },
      inactiveClientsCount
    });

    let systemPrompt = "";
    if (language === "English") {
      systemPrompt = `You are Repos, the proactive autonomous e-commerce assistant of W-COM.
[STORE DATA]
${storeContext}
[SMART INSIGHTS (JSON)]
${insightsText}
YOUR NEW AUTONOMOUS CAPABILITIES:
1. Stock Forecasting: Analyze 'stockAlerts' to prevent stockouts.
2. Smart Pricing: Use 'smartPricing' to suggest targeted promotions on dormant stocks or suggest increasing prices slightly for high-demand products.
3. Briefing: Use 'dailyBriefing' to summarize performance.
4. Marketing Campaign: Analyze 'inactiveClientsCount'. If > 0, proactively propose to send a push/in-app campaign.
5. EDIT ACTIONS (VERY IMPORTANT):
   Use the special format [ACTION:TYPE:ID:VALUE] in your reply to trigger execution:
   - Price: [ACTION:UPDATE_PRICE:productId:new_price]
   - Stock: [ACTION:UPDATE_STOCK:productId:new_stock]
   - Description: [ACTION:UPDATE_DESC:productId:new_description]
   - Order Status: [ACTION:UPDATE_ORDER_STATUS:orderId:new_status]
   - Assign Driver: [ACTION:ASSIGN_DRIVER:orderId:driverId:driverName]
   - Send Campaign: [ACTION:SEND_CAMPAIGN:discount:promoCode]
RULES:
- Be PROACTIVE. Mention alerts without being asked.
- Always reply in English.`;
    } else if (language === "Español") {
      systemPrompt = `Eres Repos, el asistente de comercio electrónico autónomo y proactivo de W-COM.
[DATOS DE TIENDA]
${storeContext}
[INFORMACIÓN INTELIGENTE (JSON)]
${insightsText}
TUS NUEVAS CAPACIDADES AUTÓNOMAS:
1. Previsión de stock: Analiza 'stockAlerts' para prevenir la falta de stock.
2. Smart Pricing: Utiliza 'smartPricing' para sugerir promociones dirigidas en inventario inactivo o sugerir aumentar los precios ligeramente.
3. Briefing: Utiliza 'dailyBriefing' para resumir el rendimiento.
4. Campaña de Marketing: Analiza 'inactiveClientsCount'. Si > 0, propone proactivamente enviar una campaña.
5. ACCIONES DE EDICIÓN (MUY IMPORTANTE):
   Utiliza el formato especial [ACTION:TYPE:ID:VALUE] en tu respuesta para activar la ejecución:
   - Precio: [ACTION:UPDATE_PRICE:productId:nuevo_precio]
   - Stock: [ACTION:UPDATE_STOCK:productId:nuevo_stock]
   - Descripción: [ACTION:UPDATE_DESC:productId:nueva_descripcion]
   - Estado del pedido: [ACTION:UPDATE_ORDER_STATUS:orderId:nuevo_estado]
   - Asignar repartidor: [ACTION:ASSIGN_DRIVER:orderId:driverId:nombreRepartidor]
   - Enviar campaña: [ACTION:SEND_CAMPAIGN:descuento:códigoPromo]
REGLAS:
- Sé PROACTIVO. Si ves una alerta, menciónala.
- Responde siempre en Español.`;
    } else {
      systemPrompt = `Tu es Repos, l'assistant e-commerce autonome et proactif de W-COM.
[DONNÉES BOUTIQUE]
${storeContext}
[INSIGHTS INTELLIGENTS (JSON)]
${insightsText}
TES NOUVELLES CAPACITÉS AUTONOMES :
1. Prévision de stock : Analyse 'stockAlerts' pour prévenir des ruptures.
2. Smart Pricing : Utilise 'smartPricing' pour suggérer de créer des promotions sur les stocks dormants ou d'augmenter le prix.
3. Briefing : Utilise 'dailyBriefing'.
4. Campagne Marketing : Analyse 'inactiveClientsCount'. Si > 0, propose d'envoyer une campagne.
5. ACTIONS DE MODIFICATION (TRÈS IMPORTANT) :
   Utilise le format [ACTION:TYPE:ID:VALEUR] dans ta réponse :
   - Prix : [ACTION:UPDATE_PRICE:productId:nouveau_prix]
   - Stock : [ACTION:UPDATE_STOCK:productId:nouveau_stock]
   - Description : [ACTION:UPDATE_DESC:productId:nouvelle_description]
   - Statut Commande : [ACTION:UPDATE_ORDER_STATUS:orderId:nouveau_statut]
   - Assigner Livreur : [ACTION:ASSIGN_DRIVER:orderId:driverId:nomLivreur]
   - Envoyer Campagne : [ACTION:SEND_CAMPAIGN:remise:codePromo]
RÈGLES :
- Sois PROACTIF.
- Réponds toujours en Français.`;
    }

    const messagesForApi = [
      { role: "system", content: systemPrompt },
      ...safeHistory
    ];

    if (image && typeof image === 'string' && image.length < 5000000) {
       messagesForApi.push({
         role: "user",
         content: [
           { type: "text", text: (language === "English" ? "Here is the image to analyze:" : "Voici l'image à analyser :") },
           { type: "image_url", image_url: { url: image.startsWith("data:") ? image : `data:image/jpeg;base64,${image}` } }
         ]
       });
    }

    messagesForApi.push({ role: "user", content: message });

    const abortController = new AbortController();
    const timeout = setTimeout(() => abortController.abort(), 60000);

    const nvidiaResponse = await fetch('https://integrate.api.nvidia.com/v1/chat/completions', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json; charset=utf-8',
        Authorization: `Bearer ${process.env.NVIDIA_API_KEY}`,
      },
      signal: abortController.signal,
      body: JSON.stringify({
        model: 'meta/llama-3.2-90b-vision-instruct',
        messages: messagesForApi,
        max_tokens: 500,
        temperature: 0.6,
        top_p: 0.9,
      }),
    });
    
    clearTimeout(timeout);

    if (!nvidiaResponse.ok) {
      const errorText = await nvidiaResponse.text();
      throw new Error(`NVIDIA API Error: ${nvidiaResponse.status} ${errorText}`);
    }

    const data = await nvidiaResponse.json();
    const replyText = data.choices && data.choices[0] && data.choices[0].message ? data.choices[0].message.content : '';

    res.status(200).json({ text: replyText });

  } catch (e) {
    if (e.name === 'AbortError') {
      return res.status(504).json({ error: 'NVIDIA API timeout' });
    }
    console.error('/ai/repos-assistant error:', e);
    res.status(e.statusCode || 500).json({ error: e.message });
  }
});

// PHASE 1G.2.2 : SUMMARIZE CHAT ENDPOINT
// ==========================================
// PHASE 1G.3.2 : PRODUCT CONTENT ENDPOINT
// ==========================================
const productContentRateLimits = new Map();

app.post('/ai/product-content', async (req, res) => {
  try {
    const decoded = await requireAuth(req);
    const uid = decoded.uid;

    const now = Date.now();
    const userLimit = productContentRateLimits.get(uid) || { count: 0, windowStart: now };
    if (now - userLimit.windowStart > 60000) {
      userLimit.count = 1;
      userLimit.windowStart = now;
    } else {
      userLimit.count++;
      if (userLimit.count > 15) {
        return res.status(429).json({
          error: 'rate_limit_exceeded',
          message: 'Too many AI requests. Please try again later.'
        });
      }
    }
    productContentRateLimits.set(uid, userLimit);

    let { operation, language, productDetails, taggedProductIds } = req.body || {};

    const ALLOWED_OPERATIONS = new Set(['description', 'lookbook']);
    if (!operation || !ALLOWED_OPERATIONS.has(operation)) {
      return res.status(400).json({ error: 'invalid operation' });
    }

    const ALLOWED_LANGUAGES = new Set(['French', 'English', 'Español']);
    if (language == null) {
      language = 'French';
    } else if (!ALLOWED_LANGUAGES.has(language) && language !== 'Espa\u00f1ol' && !language.startsWith('Espa')) {
      return res.status(400).json({ error: 'invalid language' });
    }
    if (language && language.startsWith('Espa')) language = 'Español';

    let systemPrompt = "";
    let userPrompt = "";
    let maxTokens = 150;
    let temperature = 0.7;

    if (operation === 'description') {
      if (!productDetails || typeof productDetails !== 'object') {
        return res.status(400).json({ error: 'productDetails required for description' });
      }

      const { name, category, price, stock } = productDetails;
      if (!name || typeof name !== 'string' || name.trim().length === 0) {
        return res.status(400).json({ error: 'invalid product name' });
      }
      if (!category || typeof category !== 'string' || category.trim().length === 0) {
        return res.status(400).json({ error: 'invalid category' });
      }
      
      const safeName = name.trim().substring(0, 200);
      const safeCategory = category.trim().substring(0, 100);
      const safePrice = String(price || '').substring(0, 50);
      const safeStock = String(stock || '').substring(0, 50);

      if (language === 'English') {
        systemPrompt = "You are an e-commerce assistant who writes precise, natural and useful product descriptions.";
        userPrompt = `Write a compelling product description in English for an Ivorian marketplace.\nProduct: ${safeName}\nCategory: ${safeCategory}\nPrice: ${safePrice}\nStock: ${safeStock || 'unspecified'}\nConstraints: 70 to 110 words, professional and warm tone, no emojis, no impossible promises, end with a short call to action.`;
      } else if (language === 'Español') {
        systemPrompt = "Eres un asistente de comercio electrónico que escribe descripciones de productos precisas, naturales y útiles.";
        userPrompt = `Redacta una descripción de producto atractiva en español para un mercado marfileño.\nProducto: ${safeName}\nCategoría: ${safeCategory}\nPrecio: ${safePrice}\nStock: ${safeStock || 'no especificado'}\nRestricciones: 70 a 110 palabras, tono profesional y cálido, sin emojis, sin promesas imposibles, termina con una llamada a la acción corta.`;
      } else {
        systemPrompt = "Tu es un assistant e-commerce qui écrit des descriptions produit précises, naturelles et utiles.";
        userPrompt = `Rédige une description produit vendeuse en français pour une marketplace ivoirienne.\nProduit: ${safeName}\nCatégorie: ${safeCategory}\nPrix: ${safePrice}\nStock: ${safeStock || 'non précisé'}\nContraintes: 70 à 110 mots, ton professionnel et chaleureux, pas d'emojis, pas de promesses impossibles, termine par un appel à l'action court.`;
      }
      
      maxTokens = 220;
      temperature = 0.7;

    } else if (operation === 'lookbook') {
      if (!Array.isArray(taggedProductIds) || taggedProductIds.length === 0) {
        return res.status(400).json({ error: 'taggedProductIds array required for lookbook' });
      }
      if (taggedProductIds.length > 50) {
        return res.status(400).json({ error: 'too many tagged products' });
      }

      if (!db) {
        return res.status(503).json({ error: 'firestore not configured' });
      }

      // Chunk reads if necessary, but usually under 10 items. Firestore IN allows max 30.
      const idsToFetch = taggedProductIds.slice(0, 30).filter(id => typeof id === 'string' && id.trim().length > 0);
      
      if (idsToFetch.length === 0) {
        return res.status(400).json({ error: 'no valid product ids provided' });
      }

      const productsSnap = await db.collection('products')
        .where(admin.firestore.FieldPath.documentId(), 'in', idsToFetch)
        .get();

      if (productsSnap.empty) {
        return res.status(404).json({ error: 'no products found' });
      }

      // VERIFICATION: Check ownership of the store(s) for the retrieved products
      const storeIds = new Set();
      const productDocs = productsSnap.docs;
      for (const pDoc of productDocs) {
        const storeId = pDoc.data().storeId;
        if (storeId) storeIds.add(storeId);
      }

      for (const storeId of storeIds) {
        const storeSnap = await db.collection('stores').doc(storeId).get();
        if (!storeSnap.exists || storeSnap.data().ownerId !== uid) {
          return res.status(403).json({ error: 'access denied to one or more products' });
        }
      }

      const noDescText = language === 'English' ? 'No description' : (language === 'Español' ? 'Sin descripción' : 'Pas de description');
      const productsInfoList = productDocs.map(doc => {
        const p = doc.data();
        const priceCfa = p.price != null ? `${p.price} CFA` : '';
        const desc = p.description ? p.description : noDescText;
        return `- ${p.name || 'Produit'} (${priceCfa}) : ${desc}`;
      }).join('\n');

      if (language === 'English') {
        systemPrompt = "You are a renowned e-commerce literary writer (named Repos) specialized in storytelling for fashion and craft collections.";
        userPrompt = `Write a captivating and immersive narrative story in English to present these products in a Lookbook / Fashion-Beauty-Style Editorial.\nProducts:\n${productsInfoList}\n\nConstraints:\n- Length: 150 to 250 words.\n- Immersive and poetic tone, like a creator's blog or a Wattpad chapter.\n- No emojis, weave in beautiful metaphors around these pieces.\n- Make clear paragraphs separated by line breaks.`;
      } else if (language === 'Español') {
        systemPrompt = "Eres un reconocido escritor literario de comercio electrónico (llamado Repos) especializado en storytelling de colecciones de moda y artesanía.";
        userPrompt = `Redacta una historia narrativa cautivadora e inmersiva en español para presentar estos productos en un Lookbook / Editorial de moda/belleza/estilo.\nProductos:\n${productsInfoList}\n\nRestricciones:\n- Longitud: 150 a 250 palabras.\n- Tono inmersivo y poético, tipo blog de creador o capítulo de Wattpad.\n- Sin emojis, incorpora hermosas metáforas alrededor de estas piezas.\n- Haz párrafos claros separados por saltos de línea.`;
      } else {
        systemPrompt = "Tu es un rédacteur littéraire e-commerce de renom (nommé Repos) spécialisé dans le storytelling de collections de mode et d'artisanat.";
        userPrompt = `Rédige une histoire narrative captivante et immersive en français pour présenter ces produits dans un Lookbook / Éditorial de mode/beauté/style.\nProduits :\n${productsInfoList}\n\nContraintes :\n- Longueur: 150 à 250 mots.\n- Ton immersif et poétique, type blog de créateur ou chapitre Wattpad.\n- Pas d'emojis, intègre de magnifiques métaphores autour de ces pièces.\n- Fais des paragraphes clairs espacés par des sauts de ligne.`;
      }

      maxTokens = 500;
      temperature = 0.75;
    }

    const abortController = new AbortController();
    const timeout = setTimeout(() => abortController.abort(), 60000);

    const nvidiaResponse = await fetch('https://integrate.api.nvidia.com/v1/chat/completions', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json; charset=utf-8',
        Authorization: `Bearer ${process.env.NVIDIA_API_KEY}`,
      },
      signal: abortController.signal,
      body: JSON.stringify({
        model: 'meta/llama-3.2-11b-vision-instruct',
        messages: [
          { role: 'system', content: systemPrompt },
          { role: 'user', content: userPrompt }
        ],
        max_tokens: maxTokens,
        temperature: temperature,
        top_p: 0.9
      }),
    });

    clearTimeout(timeout);

    if (!nvidiaResponse.ok) {
      const errText = await nvidiaResponse.text();
      console.error(`NVIDIA API Error (/ai/product-content): ${nvidiaResponse.status} ${nvidiaResponse.statusText}`);
      return res.status(500).json({ error: 'AI provider error' });
    }

    const nvidiaData = await nvidiaResponse.json();
    const replyText = nvidiaData.choices?.[0]?.message?.content || "";
    
    if (!replyText) {
      return res.status(500).json({ error: 'AI returned empty response' });
    }

    return res.json({ text: replyText });
  } catch (error) {
    if (error.name === 'AbortError') {
      console.error("NVIDIA API Timeout (/ai/product-content)");
      return res.status(504).json({ error: 'timeout', message: 'Request to AI provider timed out.' });
    }
    console.error("Error in /ai/product-content:", error.message);
    if (error.message && error.message.includes('auth')) {
      return res.status(401).json({ error: 'unauthorized', message: 'Authentication failed' });
    }
    return res.status(500).json({ error: 'internal_error' });
  }
});

// ---------------------------
// Endpoint d�di� sp�cifique pour le Marketing (Phase 1G.4.2)
// S�curis� : Authentification, Validation stricte des inputs, Mod�le et Prompt serveur
// ---------------------------
const marketingRateLimits = new Map();

app.post('/ai/marketing', async (req, res) => {
  try {
    const decoded = await requireAuth(req);
    const uid = decoded.uid;

    const now = Date.now();
    const userLimit = marketingRateLimits.get(uid) || { count: 0, windowStart: now };
    if (now - userLimit.windowStart > 60000) {
      userLimit.count = 1;
      userLimit.windowStart = now;
    } else {
      userLimit.count++;
      if (userLimit.count > 15) {
        return res.status(429).json({ error: 'rate_limit', message: 'Too many requests for Marketing AI' });
      }
    }
    marketingRateLimits.set(uid, userLimit);

    const { operation, language = 'French' } = req.body;
    
    if (!['French', 'English', 'Espa�ol'].includes(language)) {
      return res.status(400).json({ error: 'invalid_language' });
    }

    let systemPrompt = '';
    let userPrompt = '';

    if (operation === 'caption') {
      const { platform, tone, productName, city, options } = req.body;
      
      if (typeof platform !== 'string' || platform.length > 50) return res.status(400).json({ error: 'invalid_platform' });
      if (typeof productName !== 'string' || productName.length > 150) return res.status(400).json({ error: 'invalid_productName' });
      
      const safeTone = (typeof tone === 'string' && tone.length <= 50) ? tone.replace(/"/g, '') : 'Vendeur';
      const safeCity = (typeof city === 'string' && city.length <= 50) ? city : 'Abidjan';
      
      const emojis = !!options?.emojis;
      const hashtags = !!options?.hashtags;
      const cta = !!options?.cta;
      const promo = !!options?.promo;
      const location = !!options?.location;

      if (language === 'English') {
        systemPrompt = `You are a digital marketing expert for e-commerce in Ivory Coast.\nGenerate 3 variants of captions for ${platform} with tone "${safeTone}".`;
        if (platform.toLowerCase().includes('whatsapp status') || platform.toLowerCase() === 'whatsapp') {
          systemPrompt = `You are a digital marketing expert for e-commerce in Ivory Coast.\nGenerate 3 variants of WhatsApp status with tone "${safeTone}": one short and punchy, one narrative/emotional, and one aggressive flash-sale style.`;
        }
        userPrompt = `Product: ${productName}\nLocation: ${safeCity}\nOptions: Emojis=${emojis}, Hashtags=${hashtags}, CTA=${cta}, Promo=${promo}, Location=${location}\n\nRespond ONLY with a JSON array of 3 strings, one per line, without markdown.`;
      } else if (language === 'Espa�ol') {
        systemPrompt = `Eres un experto en marketing digital para el comercio electr�nico en Costa de Marfil.\nGenera 3 variantes de captions para ${platform} con el tono "${safeTone}".`;
        if (platform.toLowerCase().includes('whatsapp status') || platform.toLowerCase() === 'whatsapp') {
          systemPrompt = `Eres un experto en marketing digital para el comercio electr�nico en Costa de Marfil.\nGenera 3 variantes de estado de WhatsApp con el tono "${safeTone}": una corta e impactante, una narrativa/emotiva, y una agresiva estilo venta flash.`;
        }
        userPrompt = `Producto: ${productName}\nUbicaci�n: ${safeCity}\nOpciones: Emojis=${emojis}, Hashtags=${hashtags}, CTA=${cta}, Promo=${promo}, Ubicaci�n=${location}\n\nResponde �NICAMENTE con un array JSON de 3 strings, uno por l�nea, sin markdown.`;
      } else {
        systemPrompt = `Tu es un expert en marketing digital pour le e-commerce en C�te d'Ivoire.\nG�n�re 3 variantes de captions pour ${platform} avec le ton "${safeTone}".`;
        if (platform.toLowerCase().includes('whatsapp status') || platform.toLowerCase() === 'whatsapp') {
          systemPrompt = `Tu es un expert en marketing digital pour le e-commerce en C�te d'Ivoire.\nG�n�re 3 variantes de statut WhatsApp avec le ton "${safeTone}" : une courte et percutante, une storytelling/�motive, une agressive style vente flash.`;
        }
        userPrompt = `Produit : ${productName}\nLocalisation : ${safeCity}\nOptions : Emojis=${emojis}, Hashtags=${hashtags}, CTA=${cta}, Promo=${promo}, Mention localisation=${location}\n\nR�ponds UNIQUEMENT avec un JSON array de 3 strings, une par ligne, sans markdown.`;
      }

    } else if (operation === 'campaign') {
      const { channel, campaignName, productNames } = req.body;
      
      if (typeof channel !== 'string' || channel.length > 50) return res.status(400).json({ error: 'invalid_channel' });
      if (typeof campaignName !== 'string' || campaignName.length > 100) return res.status(400).json({ error: 'invalid_campaignName' });
      
      const safeProductNames = (typeof productNames === 'string') ? productNames.substring(0, 300) : 'divers produits';
      const ctaWhatsAppFr = channel.toLowerCase() === 'whatsapp' ? "Inclus un appel � l'action pour contacter le vendeur et commander." : "";
      const ctaWhatsAppEn = channel.toLowerCase() === 'whatsapp' ? "Include a call to action to contact the seller and order." : "";
      const ctaWhatsAppEs = channel.toLowerCase() === 'whatsapp' ? "Incluye una llamada a la acci�n para escribir al vendedor y pedir." : "";
      
      if (language === 'English') {
        systemPrompt = `You are a digital marketing expert for e-commerce in Ivory Coast.\nGenerate 3 short variants of marketing messages for a "${channel}" campaign named "${campaignName}".`;
        userPrompt = `Featured products: ${safeProductNames}\n${ctaWhatsAppEn}\n\nRespond ONLY with a JSON array of 3 strings, without markdown.`;
      } else if (language === 'Espa�ol') {
        systemPrompt = `Eres un experto en marketing digital para el comercio electr�nico en Costa de Marfil.\nGenera 3 variantes cortas de mensajes de marketing para una campa�a "${channel}" llamada "${campaignName}".`;
        userPrompt = `Productos destacados: ${safeProductNames}\n${ctaWhatsAppEs}\n\nResponde �NICAMENTE con un array JSON de 3 strings, sin markdown.`;
      } else {
        systemPrompt = `Tu es un expert en marketing digital pour le e-commerce en C�te d'Ivoire.\nG�n�re 3 variantes courtes de messages marketing pour une campagne "${channel}" nomm�e "${campaignName}".`;
        userPrompt = `Produits mis en avant : ${safeProductNames}\n${ctaWhatsAppFr}\n\nR�ponds UNIQUEMENT avec un JSON array de 3 strings, sans markdown.`;
      }
    } else {
      return res.status(400).json({ error: 'invalid_operation' });
    }

    const abortController = new AbortController();
    const timeout = setTimeout(() => abortController.abort(), 60000);

    const nvidiaResponse = await fetch('https://integrate.api.nvidia.com/v1/chat/completions', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json; charset=utf-8',
        Authorization: `Bearer ${process.env.NVIDIA_API_KEY}`,
      },
      signal: abortController.signal,
      body: JSON.stringify({
        model: 'meta/llama-3.2-11b-vision-instruct',
        messages: [
          { role: 'system', content: systemPrompt },
          { role: 'user', content: userPrompt }
        ],
        max_tokens: 500,
        temperature: 0.8,
        top_p: 0.9
      }),
    });

    clearTimeout(timeout);

    if (!nvidiaResponse.ok) {
      console.error(`NVIDIA API Error (/ai/marketing): ${nvidiaResponse.status} ${nvidiaResponse.statusText}`);
      return res.status(500).json({ error: 'AI provider error' });
    }

    const nvidiaData = await nvidiaResponse.json();
    const replyText = nvidiaData.choices?.[0]?.message?.content || "";
    
    if (!replyText) {
      return res.status(500).json({ error: 'AI returned empty response' });
    }

    let variants = [];
    try {
      let cleanText = replyText.trim();
      if (cleanText.startsWith('```json')) {
        cleanText = cleanText.substring(7);
      } else if (cleanText.startsWith('```')) {
        cleanText = cleanText.substring(3);
      }
      if (cleanText.endsWith('```')) {
        cleanText = cleanText.substring(0, cleanText.length - 3);
      }
      cleanText = cleanText.trim();

      const parsed = JSON.parse(cleanText);
      if (Array.isArray(parsed)) {
        variants = parsed.map(e => String(e).trim());
      } else {
        throw new Error('Not a JSON array');
      }
    } catch (parseError) {
      variants = replyText.split('\n')
        .map(line => line.trim())
        .filter(line => line.length > 0 && !line.startsWith('[') && !line.startsWith(']'))
        .slice(0, 3);
    }
    
    if (variants.length === 0) {
      return res.status(500).json({ error: 'AI generated invalid format' });
    }

    if (variants.length > 3) {
      variants = variants.slice(0, 3);
    }

    return res.json({ variants });
  } catch (error) {
    if (error.name === 'AbortError') {
      console.error("NVIDIA API Timeout (/ai/marketing)");
      return res.status(504).json({ error: 'timeout', message: 'Request to AI provider timed out.' });
    }
    console.error("Error in /ai/marketing:", error.message);
    if (error.message && error.message.includes('auth')) {
      return res.status(401).json({ error: 'unauthorized', message: 'Authentication failed' });
    }
    return res.status(500).json({ error: 'internal_error' });
  }
});


const summarizeRateLimits = new Map();

app.post('/ai/summarize-chat', async (req, res) => {
  try {
    const decoded = await requireAuth(req);
    const uid = decoded.uid;

    const now = Date.now();
    const userLimit = summarizeRateLimits.get(uid) || { count: 0, windowStart: now };
    if (now - userLimit.windowStart > 60000) {
      userLimit.count = 1;
      userLimit.windowStart = now;
    } else {
      userLimit.count++;
      if (userLimit.count > 15) {
        return res.status(429).json({
          error: 'rate_limit_exceeded',
          message: 'Too many AI requests. Please try again later.'
        });
      }
    }
    summarizeRateLimits.set(uid, userLimit);

    let { chatContent, type, language } = req.body || {};

    if (chatContent == null || typeof chatContent !== 'string') {
      return res.status(400).json({ error: 'chatContent is required and must be a string' });
    }
    chatContent = chatContent.trim();
    if (chatContent.length === 0) {
      return res.status(400).json({ error: 'chatContent cannot be empty' });
    }
    if (chatContent.length > 4000) {
      chatContent = chatContent.substring(0, 4000);
    }

    const ALLOWED_SUMMARY_TYPES = new Set(['customer', 'workspace']);
    if (type == null) {
      type = 'customer';
    } else if (!ALLOWED_SUMMARY_TYPES.has(type)) {
      return res.status(400).json({ error: 'Invalid type' });
    }

    const ALLOWED_LANGUAGES = new Set(['French', 'English', 'Español']);
    if (language == null) {
      language = 'French';
    } else if (!ALLOWED_LANGUAGES.has(language) && language !== 'Espa\u00f1ol' && !language.startsWith('Espa')) {
      return res.status(400).json({ error: 'Invalid language' });
    }
    if (language && language.startsWith('Espa')) language = 'Español';

    let systemPrompt = "";
    if (type === 'customer') {
      if (language === 'English') {
        systemPrompt = "You are the AI assistant of W-COM. Summarize this commercial conversation in 2 to 3 sentences. Highlight the main intent, important requests, and useful elements for the seller. Be factual and concise. Do not create any information not present in the conversation.";
      } else if (language === 'Español') {
        systemPrompt = "Eres el asistente de IA de W-COM. Resume esta conversación comercial en 2 a 3 oraciones. Destaca la intención principal, las solicitudes importantes y los elementos útiles para el vendedor. Sé factual y conciso. No crees información que no esté en la conversación.";
      } else {
        systemPrompt = "Tu es l'assistant IA de W-COM. Résume cette conversation commerciale en 2 à 3 phrases. Mets en évidence l'intention principale, les demandes importantes et les éléments utiles pour le vendeur. Reste factuel et concis. Ne crée aucune information absente de la conversation.";
      }
    } else if (type === 'workspace') {
      if (language === 'English') {
        systemPrompt = "You are the AI assistant of W-COM Workspace. Summarize this professional conversation in 2 to 3 sentences. Highlight decisions, problems, important requests, and next actions when explicitly present. Be factual and concise. Do not create any information not present in the conversation.";
      } else if (language === 'Español') {
        systemPrompt = "Eres el asistente de IA de W-COM Workspace. Resume esta conversación profesional en 2 a 3 oraciones. Destaca decisiones, problemas, solicitudes importantes y próximos pasos cuando estén explícitamente presentes. Sé factual y conciso. No crees información que no esté en la conversación.";
      } else {
        systemPrompt = "Tu es l'assistant IA de W-COM Workspace. Résume cette conversation professionnelle en 2 à 3 phrases. Mets en évidence les décisions, problèmes, demandes importantes et prochaines actions lorsqu'elles sont explicitement présentes. Reste factuel et concis. Ne crée aucune information absente de la conversation.";
      }
    }

    const abortController = new AbortController();
    const timeout = setTimeout(() => abortController.abort(), 60000);

    const nvidiaResponse = await fetch('https://integrate.api.nvidia.com/v1/chat/completions', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json; charset=utf-8',
        Authorization: `Bearer ${process.env.NVIDIA_API_KEY}`,
      },
      signal: abortController.signal,
      body: JSON.stringify({
        model: 'meta/llama-3.2-11b-vision-instruct',
        messages: [
          { role: 'system', content: systemPrompt },
          { role: 'user', content: chatContent }
        ],
        max_tokens: 150,
        temperature: 0.3,
        top_p: 0.9
      }),
    });

    clearTimeout(timeout);

    if (!nvidiaResponse.ok) {
      const errText = await nvidiaResponse.text();
      console.error(`NVIDIA API Error (/ai/summarize-chat): ${nvidiaResponse.status} ${nvidiaResponse.statusText}`);
      return res.status(500).json({ error: 'AI provider error' });
    }

    const nvidiaData = await nvidiaResponse.json();
    const replyText = nvidiaData.choices?.[0]?.message?.content || "";

    return res.json({ text: replyText });
  } catch (error) {
    if (error.name === 'AbortError') {
      console.error("NVIDIA API Timeout (/ai/summarize-chat)");
      return res.status(504).json({ error: 'timeout', message: 'Request to AI provider timed out.' });
    }
    console.error("Error in /ai/summarize-chat:", error.message);
    if (error.message && error.message.includes('auth')) {
      return res.status(401).json({ error: 'unauthorized', message: 'Authentication failed' });
    }
    return res.status(500).json({ error: 'internal_error' });
  }
});


// ---------------------------
// Endpoint dAcclAc spAccifique pour le Workspace Copilot (Phase 1F.4)
// SAccurisAc : Authentification, Autorisation Workspace, AgrAcgation Firestore
// et Prompt Engineering sAccurisAc cAtAc serveur.
// ---------------------------
const aiRateLimits = new Map();

app.post('/ai/workspace-copilot', async (req, res) => {
  try {
    // 1. Authentification Firebase
    const decoded = await requireAuth(req);
    const uid = decoded.uid;

    // Rate Limiting (en mAcmOire, basique : max 10 requAtes / minute / UID)
    const now = Date.now();
    const userLimit = aiRateLimits.get(uid) || { count: 0, windowStart: now };
    if (now - userLimit.windowStart > 60000) {
      userLimit.count = 1;
      userLimit.windowStart = now;
    } else {
      userLimit.count++;
      if (userLimit.count > 10) {
        return res.status(429).json({ error: 'Rate limit exceeded. Please wait.' });
      }
    }
    aiRateLimits.set(uid, userLimit);

    const { workspaceId, message, history } = req.body || {};

    if (!workspaceId) {
      return res.status(400).json({ error: 'workspaceId required' });
    }
    if (!message) {
      return res.status(400).json({ error: 'message required' });
    }

    if (!db) {
      return res.status(500).json({ error: 'Firestore not initialized' });
    }

    // 2. VAcrification d'Autorisation Workspace (RAcservAc Admin/Manager)
    const memberSnap = await db.collection('workspaces').doc(workspaceId).collection('members').doc(uid).get();
    if (!memberSnap.exists) {
      return res.status(403).json({ error: 'Access denied: not a workspace member' });
    }
    const role = memberSnap.data().role;
    if (role !== 'admin' && role !== 'manager') {
      return res.status(403).json({ error: 'Access denied: Copilot requires admin or manager role' });
    }

    // 3. AgrAcgation du Contexte Firestore (cAtAc serveur)
    let contextBuffer = '';
    try {
      const projSnap = await db.collection('workspaces').doc(workspaceId).collection('projects').limit(5).get();
      if (!projSnap.empty) {
        contextBuffer += '\nProjets en cours :\n';
        projSnap.forEach(doc => {
          const d = doc.data();
          contextBuffer += `- ${d.title || d.name || 'Projet'} (Progression: ${d.progress || 0}%, Statut: ${d.status || 'En cours'})\n`;
        });
      }

      const candSnap = await db.collection('workspaces').doc(workspaceId).collection('applications').limit(5).get();
      if (!candSnap.empty) {
        contextBuffer += '\nCandidatures rAccentes :\n';
        candSnap.forEach(doc => {
          const d = doc.data();
          contextBuffer += `- ${d.name || d.candidateName || 'Candidat'} pour le poste "${d.role || d.jobTitle || 'Poste'}" (Statut: ${d.status || 'En attente'})\n`;
        });
      }

      let teamSnap = await db.collection('workspaces').doc(workspaceId).collection('team').limit(6).get();
      if (teamSnap.empty) {
        teamSnap = await db.collection('workspaces').doc(workspaceId).collection('members').limit(6).get();
      }
      if (!teamSnap.empty) {
        contextBuffer += '\nMembres de l\'equipe :\n';
        teamSnap.forEach(doc => {
          const d = doc.data();
          contextBuffer += `- ${d.name || d.displayName || 'Membre'} (${d.role || 'worker'})\n`;
        });
      }
    } catch (e) {
      console.error('Erreur lors de la rAccupAcration du contexte Firestore:', e);
    }

    // 4. Prompt Engineering SAccurisAc
    const systemPrompt = `Tu es Repos AI (dY - Repos), l'assistant intelligent, autonome et amical de cet espace de travail W-COM.
Tu peux discuter de maniA"re fluide, naturelle et professionnelle de tout sujet (salutations, actualitAcs, conseils stratAcgiques, mActAco, travail quotidien, gestion de projet, etc.).

Voici les donnAces en direct de l'espace de travail :
${contextBuffer.trim() === '' ? 'Aucune donnAce enregistrAce pour le moment.' : contextBuffer.trim()}

INSTRUCTIONS IMPORTANTES :
1. RAcponds toujours en franA ais dans un style chaleureux, dynamique, bienveillant et concis (avec des emojis adaptAcs).
2. Si l'utilisateur te demande de CRA%ER une tAche (ou s'il exprime une action claire du type "crAce une tAche pour X", "ajoute une tAche", "fais une tAche"), rAcponds amicalement en expliquant ce que tu prAcpares, ET ajoute OBLIGATOIREMENT A la fin exacte de ton message ce tag spAccial :
[ACTION_PROPOSAL: {"type": "createTask", "title": "<Titre court de la tAche>", "description": "<Description claire de la tAche>", "targetAssignee": "<Nom de la personne ou Acquipe>", "priority": "Normale"}]
3. Tu as accA"s aux donnAces de projets et de candidatures ci-dessus. Utilise-les pour donner des rAcponses prAccises et personnalisAces.`;

    const apiMessages = [{ role: 'system', content: systemPrompt }];

    // Ajout de l'historique bridAc cAtAc serveur (max 8 messages)
    if (Array.isArray(history)) {
      const recentHistory = history.length > 8 ? history.slice(-8) : history;
      recentHistory.forEach(msg => {
        if (msg.role && msg.content) {
          apiMessages.push({ role: msg.role === 'user' ? 'user' : 'assistant', content: msg.content });
        }
      });
    }

    // Ajout de la nouvelle requAte
    apiMessages.push({ role: 'user', content: message });

    // 5. Appel sAccurisAc A NVIDIA
    const targetModel = 'meta/llama-3.2-90b-vision-instruct';

    const nvidiaResponse = await fetch(
      'https://integrate.api.nvidia.com/v1/chat/completions',
      {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json; charset=utf-8',
          Authorization: `Bearer ${process.env.NVIDIA_API_KEY}`,
        },
        body: JSON.stringify({
          model: targetModel,
          messages: apiMessages,
          max_tokens: 700,
          temperature: 0.7,
        }),
      }
    );

    const data = await nvidiaResponse.json();
    res.status(nvidiaResponse.status).json(data);
  } catch (e) {
    console.error('/ai/workspace-copilot error:', e);
    res.status(e.statusCode || 500).json({ error: e.message });
  }
});

// ---------------------------
// Proxy generique vers OneSignal (envoi de notifications push) -- avant,
// ONESIGNAL_REST_API_KEY etait embarquee dans le .env de l'app et appelee
// directement depuis au moins 10 fichiers client (chat, avis produits,
// reactivation clients, abonnements boutique, vente eclair, Workspace...),
// extractible d'un APK (audit du 2026-09-06). Cette cle permet d'envoyer une
// notification a n'importe quel segment/utilisateur OneSignal de l'app --
// bien plus grave qu'une simple cle IA : extraite, elle aurait permis de
// spammer/phisher l'integralite des utilisateurs de l'app, pas seulement de
// consommer un quota. app_id force cote serveur (non secret, deja en dur
// cote client, mais autant rester la seule source de verite). Le reste du
// payload (cible, titre, contenu, son, data) est transmis tel quel : chaque
// appelant construit deja ce payload lui-meme, rien dedans n'est sensible.
// Authentification Firebase requise -- n'empeche pas un utilisateur connecte
// de cibler un segment plus large que prevu (ex: 'Subscribed Users' au lieu
// des seuls abonnes de sa boutique, deja le comportement existant de
// flash_sale_screen.dart avant ce correctif), mais ferme l'exposition totale
// et anonyme de la cle qui permettait de le faire sans meme avoir de compte.
// ---------------------------
app.post('/notifications/push', async (req, res) => {
  try {
    await requireAuth(req);
    if (!process.env.ONESIGNAL_REST_API_KEY) {
      return res.status(503).json({ error: 'onesignal not configured' });
    }

    const payload = { ...(req.body || {}), app_id: ONESIGNAL_APP_ID };

    const oneSignalResponse = await fetch(
      'https://onesignal.com/api/v1/notifications',
      {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json; charset=utf-8',
          Authorization: `Basic ${process.env.ONESIGNAL_REST_API_KEY}`,
        },
        body: JSON.stringify(payload),
      }
    );

    const data = await oneSignalResponse.json().catch(() => ({}));
    res.status(oneSignalResponse.status).json(data);
  } catch (e) {
    console.error(e);
    res.status(e.statusCode || 500).json({ error: e.message });
  }
});

app.get('/', (req, res) => {
  res.send('W‑Com Genius Pay backend is running');
});

// ---------------------------
// Tache planifiee (toutes les 5 minutes) -- reevalue automatiquement deux
// champs que plus rien cote client ne remettait jamais a jour dans le temps
// (signale par l'utilisateur 2026-09-05) :
// - isShopOpen (horaires d'ouverture, settings_screen.dart) : n'etait
//   recalcule qu'au moment ou le vendeur sauvegardait un reglage, jamais
//   ensuite -- une boutique "ouverte 9h-18h" restait "ouverte" pour
//   toujours passe 18h tant que personne ne retouchait aux reglages.
// - isActive (abonnement) : rien ne desactivait jamais une boutique dont
//   l'abonnement a reellement expire (resilie puis expire, ou simplement
//   jamais renouvele) -- elle restait achetable indefiniment cote
//   acheteurs alors que le vendeur a deja perdu l'acces a son dashboard
//   (seller_dashboard.dart bloque deja l'ACCES vendeur via subscriptionDate,
//   mais ne touche jamais au document stores).
//
// Hypothese assumee : le serveur tourne en UTC, qui correspond a l'heure
// d'Abidjan (GMT, pas de changement d'heure) -- coherent avec le reste de
// l'app, deja centree sur la Cote d'Ivoire (communes d'Abidjan en dur dans
// checkout_screen.dart). A revoir si l'app s'etend a un fuseau different.
// ---------------------------

// Meme logique exacte que settings_screen.dart::_updateStoreStatusBasedOnTime
// (client), reprise ici cote serveur pour etre reevaluee dans le temps sans
// dependre d'une action du vendeur.
function isWithinBusinessHours(tm, now) {
  // Dart DateTime.weekday : 1=lundi ... 7=dimanche. JS Date.getDay() :
  // 0=dimanche ... 6=samedi -- conversion pour matcher selectedDays, deja
  // stocke cote client avec la convention Dart.
  const currentDay = now.getDay() === 0 ? 7 : now.getDay();
  const selectedDays = Array.isArray(tm.selectedDays)
    ? tm.selectedDays
    : [1, 2, 3, 4, 5];
  if (!selectedDays.includes(currentDay)) return false;

  const toMinutes = (value, fallbackH, fallbackM) => {
    const parts = (value || '').split(':');
    const h = parseInt(parts[0], 10);
    const m = parseInt(parts[1], 10);
    return (Number.isNaN(h) ? fallbackH : h) * 60 + (Number.isNaN(m) ? fallbackM : m);
  };

  const currentMinutes = now.getHours() * 60 + now.getMinutes();
  const startMinutes = toMinutes(tm.businessStart, 9, 0);
  const endMinutes = toMinutes(tm.businessEnd, 18, 0);
  let isOpen = currentMinutes >= startMinutes && currentMinutes < endMinutes;

  if (isOpen && tm.breakPeriodEnabled) {
    const breakStart = toMinutes(tm.breakStart, 12, 0);
    const breakEnd = toMinutes(tm.breakEnd, 13, 0);
    if (currentMinutes >= breakStart && currentMinutes < breakEnd) {
      isOpen = false;
    }
  }

  return isOpen;
}

async function reconcileBusinessHours() {
  if (!db) return;
  try {
    const usersSnap = await db
      .collection('users')
      .where('timeManagement.businessHoursEnabled', '==', true)
      .get();

    const now = new Date();
    for (const userDoc of usersSnap.docs) {
      const tm = userDoc.data().timeManagement || {};
      const storesSnap = await db
        .collection('stores')
        .where('ownerId', '==', userDoc.id)
        .limit(1)
        .get();
      if (storesSnap.empty) continue;

      const storeDoc = storesSnap.docs[0];
      const isOpen = isWithinBusinessHours(tm, now);
      if (storeDoc.data().isShopOpen !== isOpen) {
        await storeDoc.ref.update({ isShopOpen: isOpen });
      }
    }
  } catch (e) {
    console.error('❌ reconcileBusinessHours:', e.message);
  }
}

async function reconcileSubscriptionExpiry() {
  if (!db) return;
  try {
    const storesSnap = await db
      .collection('stores')
      .where('isActive', '==', true)
      .get();

    const now = new Date();
    for (const storeDoc of storesSnap.docs) {
      const ownerId = storeDoc.data().ownerId;
      if (!ownerId) continue;
      const userSnap = await db.collection('users').doc(ownerId).get();
      const subscriptionDate = userSnap.data()?.subscriptionDate;
      const expired = !subscriptionDate || subscriptionDate.toDate() < now;
      if (expired) {
        await storeDoc.ref.update({ isActive: false });
        console.log(`ℹ️ Boutique ${storeDoc.id} désactivée (abonnement expiré)`);
      }
    }
  } catch (e) {
    console.error('❌ reconcileSubscriptionExpiry:', e.message);
  }
}

// Petit relais interne vers l'API OneSignal, sans repasser par l'endpoint
// HTTP /notifications/push (evite un aller-retour reseau vers soi-meme) --
// meme cle/app_id que cet endpoint, jamais exposes au client.
async function sendOneSignalPush(payload) {
  if (!process.env.ONESIGNAL_REST_API_KEY) return;
  try {
    await fetch('https://onesignal.com/api/v1/notifications', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json; charset=utf-8',
        Authorization: `Basic ${process.env.ONESIGNAL_REST_API_KEY}`,
      },
      body: JSON.stringify({ ...payload, app_id: ONESIGNAL_APP_ID }),
    });
  } catch (e) {
    console.error('sendOneSignalPush failed:', e.message);
  }
}

// Rappel de fin d'abonnement (demande utilisateur 2026-09-08) : previent le
// vendeur 7 jours avant l'echeance, pour lui laisser le temps de se
// reabonner avant la coupure d'acces (voir reconcileSubscriptionExpiry
// ci-dessus, qui desactive la boutique des l'expiration reelle). Un seul
// rappel par cycle d'abonnement : subscriptionReminderForExpiryMs memorise
// pour QUELLE date d'expiration le rappel a deja ete envoye, et se
// desynchronise naturellement des qu'un renouvellement change cette date
// (le prochain cycle redeclenche donc son propre rappel sans etat a
// reinitialiser manuellement).
async function reconcileSubscriptionReminders() {
  if (!db) return;
  try {
    const now = new Date();
    const sevenDaysFromNow = new Date(now.getTime() + 7 * 24 * 60 * 60 * 1000);
    const usersSnap = await db
      .collection('users')
      .where('subscriptionDate', '>', now)
      .where('subscriptionDate', '<=', sevenDaysFromNow)
      .get();

    for (const userDoc of usersSnap.docs) {
      const data = userDoc.data();
      const expiry = data.subscriptionDate.toDate();
      const expiryMs = expiry.getTime();
      if (data.subscriptionReminderForExpiryMs === expiryMs) continue;

      const daysRemaining = Math.max(
        1,
        Math.ceil((expiryMs - now.getTime()) / (24 * 60 * 60 * 1000))
      );
      const planName = data.currentPlan || 'votre forfait';
      const title = '⏳ Votre abonnement expire bientôt';
      const message = `Il vous reste ${daysRemaining} jour${daysRemaining > 1 ? 's' : ''} avant la fin de votre abonnement ${planName}. Renouvelez dès maintenant pour ne pas perdre l'accès à votre boutique.`;

      await db.collection('notifications').add({
        receiverId: userDoc.id,
        title,
        message,
        type: 'subscription_reminder',
        timestamp: admin.firestore.FieldValue.serverTimestamp(),
        isRead: false,
      });

      await sendOneSignalPush({
        include_aliases: { external_id: [userDoc.id] },
        target_channel: 'push',
        headings: { en: 'Your subscription is about to expire', fr: title },
        contents: {
          en: `You have ${daysRemaining} day(s) left. Renew now to keep your store online.`,
          fr: message,
        },
        data: { type: 'subscription_reminder' },
      });

      await userDoc.ref.update({ subscriptionReminderForExpiryMs: expiryMs });
      console.log(`🔔 Rappel abonnement envoyé à ${userDoc.id} (${daysRemaining}j restants)`);
    }
  } catch (e) {
    console.error('❌ reconcileSubscriptionReminders:', e.message);
  }
}

cron.schedule('*/5 * * * *', () => {
  reconcileBusinessHours();
  reconcileSubscriptionExpiry();
  reconcileSubscriptionReminders();
});

app.listen(PORT, () => {
  console.log(`🚀 Server listening on port ${PORT}`);
});




