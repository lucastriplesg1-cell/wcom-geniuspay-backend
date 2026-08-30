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

app.get('/', (req, res) => {
  res.send('W‑Com Genius Pay backend is running');
});

app.listen(PORT, () => {
  console.log(`🚀 Server listening on port ${PORT}`);
});
