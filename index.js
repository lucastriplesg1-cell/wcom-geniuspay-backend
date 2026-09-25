// index.js
require('dotenv').config();          // loads .env locally (development only)

const express = require('express');
const cors = require('cors');
const crypto = require('crypto');
const cron = require('node-cron');
const admin = require('firebase-admin');
const cloudinary = require('cloudinary').v2;

const signUploadRateLimits = new Map();
const app = express();
app.use(cors());
// On garde le corps brut (req.rawBody) en plus du JSON parsÃ© : la vÃ©rification
// de signature du webhook Genius Pay porte sur les octets exacts envoyÃ©s, pas
// sur une version re-sÃ©rialisÃ©e par JSON.stringify (qui peut diffÃ©rer par
// l'ordre des clÃ©s ou les espaces).
app.use(express.json({
  verify: (req, res, buf) => {
    req.rawBody = buf;
  },
}));


const signDeliveryRateLimits = new Map();

// ==========================================
// CLOUDINARY SIGN-DELIVERY ENDPOINT
// ==========================================
app.post('/api/cloudinary/sign-delivery', async (req, res) => {
  try {
    const decoded = await requireAuth(req);
    const uid = decoded.uid;

    if (!process.env.CLOUDINARY_API_SECRET || !process.env.CLOUDINARY_API_KEY || !process.env.CLOUDINARY_CLOUD_NAME) {
      return res.status(500).json({ error: 'Cloudinary configuration missing' });
    }

    // Rate limiting: 60 req / min / uid
    const now = Date.now();
    const rateData = signDeliveryRateLimits.get(uid) || { count: 0, resetTime: now + 60000 };
    if (now > rateData.resetTime) {
      rateData.count = 0;
      rateData.resetTime = now + 60000;
    }
    rateData.count++;
    signDeliveryRateLimits.set(uid, rateData);
    if (rateData.count > 60) {
      return res.status(429).json({ error: 'Rate limit exceeded' });
    }

    const { public_id } = req.body || {};
    if (!public_id) {
      return res.status(400).json({ error: 'missing public_id' });
    }

    // Authorization: User can only sign URLs for their own chat_media folders
    const ecommercePrefix = `chat_media/ecommerce/${uid}/`;
    const reposPrefix = `chat_media/repos/${uid}/`;
    
    if (!public_id.startsWith(ecommercePrefix) && !public_id.startsWith(reposPrefix)) {
      console.warn(`[AuthZ] uid ${uid} attempted to access unauthorized public_id: ${public_id}`);
      return res.status(403).json({ error: 'Forbidden: Cannot access media belonging to another user' });
    }

    // Generate signed URL
    const url = cloudinary.url(public_id, {
      type: 'authenticated',
      secure: true,
      sign_url: true,
      expires_at: Math.floor(Date.now() / 1000) + 3600 // expires in 1 hour (optional but good practice)
    });

    return res.status(200).json({ url });
  } catch (err) {
    console.error('Error in /api/cloudinary/sign-delivery:', err);
    if (err.message && err.message.includes('auth')) {
      return res.status(401).json({ error: 'unauthorized', message: 'Authentication failed' });
    }
    return res.status(500).json({ error: 'Internal Server Error' });
  }
});


const PORT = process.env.PORT || 3000; // Render will inject its own PORT
const ONESIGNAL_APP_ID = '38e7126f-2c23-4ee7-b715-6db2718ea78f';

// ---------------------------
// Firebase Admin -- nÃ©cessaire pour que le webhook puisse confirmer un
// paiement dans Firestore (users/orders/subscriptionPayments/notifications).
// Best-effort : si la clÃ© de service n'est pas configurÃ©e, /payment continue
// de fonctionner normalement, seul le webhook est inopÃ©rant (avec un message
// d'erreur explicite dans les logs Ã  chaque appel).
// ---------------------------
let db = null;
try {
  const serviceAccountJson = process.env.FIREBASE_SERVICE_ACCOUNT_JSON;
  if (serviceAccountJson) {
    const serviceAccount = JSON.parse(serviceAccountJson);
    admin.initializeApp({ credential: admin.credential.cert(serviceAccount) });
    db = admin.firestore();
    console.log('âœ… Firebase Admin initialisÃ©');
  } else {
    console.warn('âš ï¸ FIREBASE_SERVICE_ACCOUNT_JSON absent -- le webhook Genius Pay ne pourra pas confirmer les paiements dans Firestore.');
  }
} catch (e) {
  console.error('âŒ Ã‰chec init Firebase Admin:', e.message);
}

// ---------------------------
// Brevo -- double canal (push + email) pour /notifications/push.
// BREVO_API_KEY / BREVO_SENDER_EMAIL / BREVO_SENDER_NAME sont a definir sur
// Render, jamais dans le code (meme logique que ONESIGNAL_REST_API_KEY).
// Best-effort : une erreur Brevo est loguee mais ne fait jamais echouer la
// reponse du endpoint (le push OneSignal reste la source de verite).
// ---------------------------
function buildBrandedEmailHtml({ title, body }) {
  const safeTitle = String(title || '').replace(/</g, '&lt;');
  const safeBody = String(body || '')
    .replace(/</g, '&lt;')
    .replace(/\n/g, '<br>');
  return `<!DOCTYPE html>
<html>
  <body style="margin:0;padding:0;background:#f4f4f4;font-family:Arial,Helvetica,sans-serif;">
    <table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="background:#f4f4f4;padding:24px 0;">
      <tr>
        <td align="center">
          <table role="presentation" width="480" cellpadding="0" cellspacing="0" style="background:#ffffff;border-radius:8px;overflow:hidden;">
            <tr>
              <td style="background:#009639;padding:20px 24px;">
                <span style="color:#ffffff;font-size:20px;font-weight:bold;letter-spacing:0.5px;">W-COM</span>
              </td>
            </tr>
            <tr>
              <td style="padding:28px 24px;">
                <h1 style="margin:0 0 12px;font-size:18px;color:#111111;">${safeTitle}</h1>
                <p style="margin:0;font-size:15px;line-height:1.5;color:#333333;">${safeBody}</p>
              </td>
            </tr>
            <tr>
              <td style="padding:16px 24px;background:#fafafa;">
                <p style="margin:0;font-size:12px;color:#999999;">
                  Vous recevez cet email car vous avez une notification associee a votre compte W-COM.
                </p>
              </td>
            </tr>
          </table>
        </td>
      </tr>
    </table>
  </body>
</html>`;
}

async function sendBrevoEmail({ to, toName, subject, title, body }) {
  if (!process.env.BREVO_API_KEY || !process.env.BREVO_SENDER_EMAIL) return;
  if (!to) return;
  try {
    const response = await fetch('https://api.brevo.com/v3/smtp/email', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Accept: 'application/json',
        'api-key': process.env.BREVO_API_KEY,
      },
      body: JSON.stringify({
        sender: {
          email: process.env.BREVO_SENDER_EMAIL,
          name: process.env.BREVO_SENDER_NAME || 'W-COM',
        },
        to: [{ email: to, name: toName || undefined }],
        subject: subject || title || 'Notification W-COM',
        htmlContent: buildBrandedEmailHtml({ title, body }),
      }),
    });
    if (!response.ok) {
      console.error('Brevo email failed:', response.status, await response.text());
    }
  } catch (e) {
    console.error('Brevo email network error:', e.message);
  }
}

// Resout les destinataires email d'un payload OneSignal : uniquement les
// envois cibles (include_aliases.external_id / include_external_user_ids),
// jamais les diffusions par segment (included_segments) -- un segment n'a
// pas de liste d'emails individuelle a cette echelle, et melanger campagne
// marketing et email transactionnel ici serait dangereux.
async function sendEmailsForPushPayload(payload) {
  if (!db || !process.env.BREVO_API_KEY) return;

  const ids = new Set([
    ...(payload.include_aliases?.external_id || []),
    ...(payload.include_external_user_ids || []),
  ]);
  if (ids.size === 0) return;

  const title = payload.headings?.fr || payload.headings?.en || '';
  const body = payload.contents?.fr || payload.contents?.en || '';
  if (!title && !body) return;

  await Promise.allSettled(
    Array.from(ids).map(async (uid) => {
      const userDoc = await db.collection('users').doc(uid).get();
      if (!userDoc.exists) return;
      const userData = userDoc.data() || {};
      if (userData.notificationsEnabled === false) return;
      if (!userData.email) return;

      await sendBrevoEmail({
        to: userData.email,
        toName: userData.name || userData.displayName,
        title,
        body,
      });
    })
  );
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
    console.error('âš ï¸ Push OneSignal Ã©chouÃ©:', e.message);
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
    console.error('âš ï¸ Push OneSignal (campagne) Ã©chouÃ©:', e.message);
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
// VÃ©rification manuelle d'une transaction (repli cÃ´tÃ© app si le webhook n'a
// pas encore confirmÃ© -- voir genius_pay_service.dart::verifyTransaction).
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
// Avant ce webhook, l'app mobile considÃ©rait une commande/un abonnement comme
// payÃ© dÃ¨s l'OUVERTURE de la page de paiement Genius Pay (openCheckout), pas
// Ã  la confirmation rÃ©elle -- un client qui annulait laissait une commande
// bloquÃ©e pour toujours, panier dÃ©jÃ  vidÃ©. Ce webhook devient la seule source
// de vÃ©ritÃ© pour "le paiement a rÃ©ellement abouti".
//
// Contrat avec l'app (lib/services/genius_pay_service.dart) : le `metadata`
// envoyÃ© Ã  la crÃ©ation du paiement revient tel quel dans `data.metadata` du
// webhook. `metadata.paymentKind` distingue :
//   - 'subscription' (payment_screen.dart)  -> userId, planName, days,
//     subscriptionPaymentId
//   - 'driver_subscription' (livreur_subscription_screen.dart) -> userId,
//     days, subscriptionPaymentId (mÃªme schÃ©ma que 'subscription', mais
//     Ã©crit sur public_drivers/{userId} au lieu de users/{userId} -- un
//     compte peut Ãªtre vendeur ET livreur en mÃªme temps, les deux
//     abonnements doivent rester indÃ©pendants)
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
    console.warn('ðŸš¨ Webhook Genius Pay rejetÃ© : signature invalide ou absente');
    return res.status(401).json({ error: 'invalid signature' });
  }

  // On accuse rÃ©ception tout de suite -- Ã©viter que Genius Pay ne renvoie le
  // mÃªme webhook en boucle pendant qu'on Ã©crit dans Firestore.
  res.status(200).json({ received: true });

  if (!db) {
    console.error(
      'âŒ Webhook reÃ§u mais Firebase Admin non configurÃ© -- paiement NON confirmÃ© dans Firestore. reference=',
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
    } else if (metadata.paymentKind === 'service_order') {
      await handleServiceOrderWebhook(status, metadata);
    } else {
      console.warn('âš ï¸ Webhook Genius Pay avec metadata.paymentKind inconnu:', metadata);
    }
  } catch (e) {
    console.error('âŒ Erreur traitement webhook Genius Pay:', e);
  }
});

async function handleSubscriptionWebhook(status, metadata) {
  const { userId, planName, days, subscriptionPaymentId } = metadata;
  if (!userId) {
    console.error('âŒ Webhook abonnement sans userId dans metadata');
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
    console.log(`â„¹ï¸ Paiement abonnement ${userId} : statut ${status}, aucun changement d'accÃ¨s`);
    return;
  }

  // Renouvellement anticipÃ© : si l'abonnement en cours n'est pas encore
  // expirÃ©, les nouveaux jours s'ajoutent Ã  sa date d'expiration au lieu de
  // repartir de maintenant -- sinon un vendeur qui renouvelle quelques jours
  // avant l'Ã©chÃ©ance perdait les jours restants dÃ©jÃ  payÃ©s (signalÃ©
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
    console.error('Lecture subscriptionDate existante Ã©chouÃ©e, base = maintenant:', e.message);
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

  console.log(`âœ… Abonnement confirmÃ© pour ${userId} (${planName}), expire le ${expiryDate.toISOString()}`);
}

// Miroir de handleSubscriptionWebhook pour l'abonnement livreur (2 500
// FCFA/mois, livreur_subscription_screen.dart) -- mÃªme logique, mais Ã©crit
// sur public_drivers/{userId} (subscriptionActive/subscriptionExpiresAt) au
// lieu de users/{userId} (isSubscribed/currentPlan), et n'active aucune
// boutique. Sans ce handler, firestore.rules::public_drivers empÃªche le
// client d'Ã©crire ces champs lui-mÃªme (audit du 2026-09-04, mÃªme faille que
// users/{userId}.isSubscribed) : le paiement resterait indÃ©finiment Ã 
// 'awaiting_checkout'.
async function handleDriverSubscriptionWebhook(status, metadata) {
  const { userId, days, subscriptionPaymentId } = metadata;
  if (!userId) {
    console.error('âŒ Webhook abonnement livreur sans userId dans metadata');
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
    console.log(`â„¹ï¸ Paiement abonnement livreur ${userId} : statut ${status}, aucun changement d'accÃ¨s`);
    return;
  }

  // MÃªme correctif que handleSubscriptionWebhook ci-dessus (2026-09-08) :
  // cumule sur la date d'expiration existante si elle n'est pas encore
  // passÃ©e, au lieu d'Ã©craser les jours restants dÃ©jÃ  payÃ©s.
  const now = Date.now();
  let baseTime = now;
  try {
    const driverSnap = await db.collection('public_drivers').doc(userId).get();
    const existingExpiry = driverSnap.data()?.subscriptionExpiresAt;
    if (existingExpiry && existingExpiry.toDate().getTime() > now) {
      baseTime = existingExpiry.toDate().getTime();
    }
  } catch (e) {
    console.error('Lecture subscriptionExpiresAt existante Ã©chouÃ©e, base = maintenant:', e.message);
  }

  const expiryDate = new Date(baseTime + Number(days || 30) * 24 * 60 * 60 * 1000);
  await db.collection('public_drivers').doc(userId).update({
    subscriptionActive: true,
    subscriptionExpiresAt: admin.firestore.Timestamp.fromDate(expiryDate),
  });

  console.log(`âœ… Abonnement livreur confirmÃ© pour ${userId}, expire le ${expiryDate.toISOString()}`);
}

function isValidOrder(order) {
  const status = order.status;
  const paymentStatus = order.paymentStatus;
  
  if (status === 'cancelled' || status === 'awaiting_payment') {
    return false;
  }
  if (paymentStatus === 'checkout_failed') {
    return false;
  }
  return true;
}

async function handleOrderWebhook(status, metadata) {
  const { orderId, buyerId, sellerId } = metadata;
  if (!orderId) {
    console.error('❌ Webhook commande sans orderId dans metadata');
    return;
  }

  const orderRef = db.collection('orders').doc(orderId);
  let sideEffects = null;

  try {
    await db.runTransaction(async (transaction) => {
      const orderSnap = await transaction.get(orderRef);
      if (!orderSnap.exists) {
        throw new Error('ORDER_NOT_FOUND');
      }
      const orderData = orderSnap.data();

      let newOrderData = null;
      if (status === 'completed') {
        newOrderData = {
          paymentStatus: 'completed',
          status: 'pending',
        };
      } else if (['failed', 'cancelled', 'expired'].includes(status)) {
        newOrderData = {
          paymentStatus: 'checkout_failed',
          status: 'cancelled',
        };
      } else {
        sideEffects = { type: 'intermediate' };
        return;
      }

      const wasValid = isValidOrder(orderData);
      const willBeValid = isValidOrder({ ...orderData, ...newOrderData });
      const delta = (willBeValid ? 1 : 0) - (wasValid ? 1 : 0);

      let chatRef = null;
      let newValidOrdersCount = null;

      if (delta !== 0) {
        const sellerIdForChat = orderData.sellerId || sellerId;
        const buyerIdForChat = orderData.buyerId || buyerId;

        if (sellerIdForChat && buyerIdForChat) {
          const chatSnap = await transaction.get(
            db.collection('chats')
              .where('sellerId', '==', sellerIdForChat)
              .where('buyerId', '==', buyerIdForChat)
              .limit(2)
          );

          if (chatSnap.size > 1) {
            console.error(`ABORTED_DUPLICATE_CHAT_RELATION for order ${orderId} (seller: ${sellerIdForChat}, buyer: ${buyerIdForChat}) - found ${chatSnap.size} chats`);
            throw new Error('ABORTED_DUPLICATE_CHAT_RELATION');
          }

          if (chatSnap.size === 1) {
            const chatDoc = chatSnap.docs[0];
            const currentCount = chatDoc.data().validOrdersCount;
            if (currentCount !== undefined && typeof currentCount !== 'number') {
               throw new Error('INVALID_COUNTER_TYPE');
            }
            const baseCount = typeof currentCount === 'number' ? currentCount : 0;
            newValidOrdersCount = baseCount + delta;
            if (newValidOrdersCount < 0) {
              throw new Error('NEGATIVE_COUNTER');
            }
            chatRef = chatDoc.ref;
          }
        }
      }

      const orderUpdatePayload = {
        ...newOrderData,
        lastUpdated: admin.firestore.FieldValue.serverTimestamp(),
      };
      
      transaction.update(orderRef, orderUpdatePayload);
      if (chatRef && newValidOrdersCount !== null) {
        transaction.update(chatRef, { validOrdersCount: newValidOrdersCount });
      }

      if (status === 'completed') {
         sideEffects = { type: 'completed', orderData };
      } else {
         sideEffects = { type: 'failed' };
      }
    });
  } catch (err) {
    if (err.message === 'ORDER_NOT_FOUND') {
      console.error(`❌ Webhook commande introuvable: ${orderId}`);
    } else {
      console.error(`❌ Webhook commande erreur transaction: ${err.message}`);
    }
    return;
  }

  if (sideEffects?.type === 'completed') {
    const orderData = sideEffects.orderData;
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
      }).catch(e => console.error(e));
      await notifySellerPush(sellerId, title, message, { amount: orderData.totalAmount }).catch(e => console.error(e));
    }

    if (buyerId) {
      try {
        const cartSnap = await db.collection('cart').where('buyerId', '==', buyerId).get();
        if (!cartSnap.empty) {
          const batch = db.batch();
          cartSnap.docs.forEach((doc) => batch.delete(doc.ref));
          await batch.commit();
        }
      } catch(e) {
        console.error(e);
      }
    }

    console.log(`✅ Commande ${orderId} confirmée payée`);
  } else if (sideEffects?.type === 'failed') {
    console.log(`ℹ️ Commande ${orderId} : paiement ${status}, panier conservé pour réessai`);
  } else if (sideEffects?.type === 'intermediate') {
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
    console.error('âŒ Webhook campagne sans campaignId dans metadata');
    return;
  }

  const campaignRef = db.collection('campaigns').doc(campaignId);
  const campaignSnap = await campaignRef.get();
  if (!campaignSnap.exists) {
    console.error(`âŒ Webhook campagne introuvable: ${campaignId}`);
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

    console.log(`âœ… Campagne ${campaignId} confirmee payee`);
  } else if (['failed', 'cancelled', 'expired'].includes(status)) {
    await campaignRef.update({
      status: 'checkout_failed',
      paymentStatus: 'checkout_failed',
      lastUpdated: admin.firestore.FieldValue.serverTimestamp(),
    });
    console.log(`â„¹ï¸ Campagne ${campaignId} : paiement ${status}`);
  } else {
    console.log(`â„¹ï¸ Campagne ${campaignId} : statut intermediaire ${status}`);
  }
}

async function handleServiceOrderWebhook(status, metadata) {
  const { workspaceId, serviceOrderId } = metadata;
  if (!workspaceId || !serviceOrderId) {
    console.error('❌ Webhook service_order sans workspaceId ou serviceOrderId');
    return;
  }

  const orderRef = db
    .collection('workspaces')
    .doc(workspaceId)
    .collection('service_orders')
    .doc(serviceOrderId);

  const orderSnap = await orderRef.get();
  if (!orderSnap.exists) {
    console.error(`❌ Service order introuvable: ${workspaceId}/${serviceOrderId}`);
    return;
  }

  if (status === 'completed') {
    await orderRef.update({
      paymentStatus: 'paid',
      lastUpdated: admin.firestore.FieldValue.serverTimestamp(),
    });
    console.log(`✅ Service order ${serviceOrderId} confirmé payé`);
  } else if (['failed', 'cancelled', 'expired'].includes(status)) {
    await orderRef.update({
      paymentStatus: 'failed',
      lastUpdated: admin.firestore.FieldValue.serverTimestamp(),
    });
    console.log(`ℹ️ Service order ${serviceOrderId} : paiement ${status}`);
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
    } else if (metadata.paymentKind === 'service_order') {
      if (metadata.clientId && metadata.clientId !== decoded.uid) {
        return res.status(403).json({ error: 'not your payment' });
      }
      if (!db) return res.status(503).json({ error: 'firestore not configured' });
      await handleServiceOrderWebhook(status, metadata);
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
    const uid = decoded.uid;
    const orderRef = db.collection('orders').doc(orderId);

    // D'abord, rAcupA"rer de maniA"re non-transactionnelle le delivery_driver si nAcessaire
    // car cela ne mute pas et Aavite de charger la transaction avec une lecture statique.
    let fleetEntryUserId = null;
    let didFetchFleet = false;
    
    // On rAalise la logique mAatier au sein de la transaction Firestore.
    const result = await db.runTransaction(async (t) => {
      const orderSnap = await t.get(orderRef);
      if (!orderSnap.exists) {
        throw new Error('ORDER_NOT_FOUND');
      }
      const order = orderSnap.data();

      // Authorization
      let isAuthorized =
        order.sellerId === uid ||
        order.livreurId === uid ||
        order.driverId === uid;

      if (!isAuthorized && order.assignedDriverId) {
        if (!didFetchFleet) {
          const fleetEntrySnap = await db.collection('delivery_drivers').doc(order.assignedDriverId).get();
          fleetEntryUserId = fleetEntrySnap.exists ? fleetEntrySnap.data().userId : null;
          didFetchFleet = true;
        }
        isAuthorized = fleetEntryUserId === uid;
      }

      if (!isAuthorized) {
        throw new Error('NOT_AUTHORIZED');
      }

      // Verrou MAatier & Idempotence
      if (order.escrowStatus !== 'in_escrow') {
        if (order.escrowStatus === 'released' || order.status === 'delivered') {
          if (!order.customerPin || order.customerPin === pin) {
             throw new Error('ALREADY_RELEASED');
          }
        }
        throw new Error('NOT_IN_ESCROW');
      }

      const paidStatuses = ['pay_on_delivery', 'test_mode_paid', 'completed'];
      if (!paidStatuses.includes(order.paymentStatus)) {
        throw new Error('PAYMENT_NOT_CONFIRMED');
      }

      if (!order.customerPin || order.customerPin !== pin) {
        throw new Error('INVALID_PIN');
      }

      const escrowId = order.escrowId;
      if (!escrowId) {
        throw new Error('NO_ESCROW');
      }
      const escrowRef = db.collection('escrow').doc(escrowId);
      const escrowSnap = await t.get(escrowRef);
      if (!escrowSnap.exists) {
        throw new Error('ESCROW_NOT_FOUND');
      }
      const escrow = escrowSnap.data();

      // RAcquisitionner les rAcfArences produits pour dAccrAcmenter le stock
      const items = order.items || [];
      const productRefs = [];
      const productSnaps = [];
      for (const item of items) {
        const productId = item.productId;
        if (productId) {
          const pRef = db.collection('products').doc(productId);
          productRefs.push(pRef);
          // On les lit dans la transaction pour Acviter les stock races
          productSnaps.push(await t.get(pRef)); 
        } else {
          productRefs.push(null);
          productSnaps.push(null);
        }
      }

      // ----------------- WRITES -----------------
      const now = admin.firestore.FieldValue.serverTimestamp();

      // 1. Order + Escrow (Statuts finaux)
      t.update(escrowRef, {
        status: 'released',
        pinValidatedAt: now,
        releasedAt: now,
      });
      t.update(orderRef, {
        escrowStatus: 'released',
        status: 'delivered',
        deliveryStatus: 'delivered',
        escrowReleasedAt: now,
        lastUpdated: now,
      });

      // 2. Stock dAduction
      const sellerId = order.sellerId || order.storeId;
      for (let i = 0; i < items.length; i++) {
        const item = items[i];
        const pRef = productRefs[i];
        const pSnap = productSnaps[i];
        
        if (!pRef || !pSnap.exists) continue;
        
        const orderedQty = Number(item.quantity) || 0;
        if (orderedQty <= 0) continue;

        const data = pSnap.data();
        const freshQty = Number(data.quantity) || 0;
        // RAcgle mActier stricte: le stock comptable ne doit jamais Aatre nAcgatif.
        const newQty = Math.max(0, freshQty - orderedQty);

        t.update(pRef, {
          quantity: newQty,
          lastUpdated: now,
        });

        // 3. Stock History
        const stockHistoryId = `${orderId}_${item.productId}`;
        t.set(db.collection('stock_history').doc(stockHistoryId), {
          productId: item.productId,
          change: -orderedQty,
          previousQty: freshQty,
          newQty: newQty,
          timestamp: now,
          userId: sellerId,
          type: 'sale'
        });
      }

      // 4. Finances : Mouvements financiers sAcurisAcs (Seller, Driver, Commission)
      const sellerAmount = Number(escrow.sellerAmount) || 0;
      const driverAmount = Number(escrow.driverAmount) || 0;
      const commissionAmount = Number(escrow.commissionAmount) || 0;
      const finalDriverId = order.assignedDriverId || order.driverId || order.livreurId;

      if (sellerId && sellerAmount > 0) {
        t.set(db.collection('transactions').doc(`${escrowId}_seller`), {
          userId: sellerId,
          type: 'sale',
          amount: sellerAmount,
          orderId: orderId,
          escrowId: escrowId,
          status: 'completed',
          description: 'Vente sAccurisAce (fonds dAcbloquAcs par code PIN)',
          createdAt: now,
        });
      }

      if (finalDriverId && driverAmount > 0) {
        t.set(db.collection('transactions').doc(`${escrowId}_driver`), {
          userId: finalDriverId,
          type: 'delivery',
          amount: driverAmount,
          orderId: orderId,
          escrowId: escrowId,
          status: 'completed',
          description: 'Frais de livraison (sAcquestre)',
          createdAt: now,
        });
      }

      if (commissionAmount > 0) {
        t.set(db.collection('commissions').doc(`${escrowId}_commission`), {
          orderId: orderId,
          escrowId: escrowId,
          amount: commissionAmount,
          sellerId: sellerId,
          sellerSubscription: escrow.sellerSubscription || 'mensuel',
          status: 'earned',
          createdAt: now,
        });
      }

      // Note : L'Aapargne automatique (VaultService) et la progression (Ascension/GradeService)
      // ne sont pas inclus ici car cela obligerait A des query() complexes et nAcessiterait 
      // de dupliquer toute la logique Flutter en Node.js (ex: boucle sur 5 niveaux d'Ascension). 
      // Ces effets secondaires "non-financiers stricts" (ou gamification) 
      // devraient faire l'objet de Cloud Functions distinctes ou Aatre migracs plus tard.

      return { success: true };
    });

    res.json(result);

  } catch (e) {
    if (e.message === 'ALREADY_RELEASED') {
       return res.json({ success: true, alreadyProcessed: true });
    }
    if (e.message === 'INVALID_PIN') {
       return res.json({ success: false });
    }
    if (e.message === 'ORDER_NOT_FOUND') return res.status(404).json({ error: 'order not found' });
    if (e.message === 'NOT_AUTHORIZED') return res.status(403).json({ error: 'not authorized for this order' });
    if (e.message === 'NOT_IN_ESCROW') return res.status(409).json({ error: 'order not in escrow' });
    if (e.message === 'PAYMENT_NOT_CONFIRMED') return res.status(409).json({ error: 'payment not confirmed' });
    if (e.message === 'NO_ESCROW') return res.status(409).json({ error: 'escrow not found for this order' });
    if (e.message === 'ESCROW_NOT_FOUND') return res.status(404).json({ error: 'escrow document not found' });

    console.error(e);
    res.status(500).json({ error: e.message });
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
      : 'franÃ§ais';
    const avgOrder = orderCount ? Number(grossRevenue) / Number(orderCount) : 0;

    const systemPrompt = `Tu es un conseiller commercial expert pour les vendeurs sur W-Com (une plateforme e-commerce africaine). Tu dois analyser les donnÃ©es du vendeur et donner 3 Ã  5 conseils concrets, pratiques et personnalisÃ©s.

RÃ¨gles de formatage obligatoires :
- RÃ©ponds **uniquement** en JSON, pas de texte en dehors
- Le JSON doit Ãªtre un tableau d'objets avec ces champs :
  - "title" (chaÃ®ne de caractÃ¨res, court, en ${lang})
  - "desc" (chaÃ®ne de caractÃ¨res, 1 Ã  2 phrases max, en ${lang})
  - "color" (chaÃ®ne de caractÃ¨res : "orange", "cyan", "yellow", "green", "purple", "red")
  - "icon" (chaÃ®ne de caractÃ¨res, nom d'icÃ´ne Material Icons : lightbulb, warning, map, shopping_cart, star, attach_money, etc.)

Exemple de rÃ©ponse valide :
[
  {"title": "Augmentez votre panier moyen", "desc": "Votre panier moyen est bas. Proposez des packs produits.", "color": "cyan", "icon": "shopping_cart"},
  {"title": "FidÃ©lisez vos clients", "desc": "Votre taux de fidÃ©litÃ© est faible. CrÃ©ez un programme de rÃ©compenses.", "color": "orange", "icon": "favorite"}
]`;

    const userPrompt = `Voici les donnÃ©es du vendeur :
- Chiffre d'affaires total (pÃ©riode sÃ©lectionnÃ©e) : ${Number(grossRevenue || 0).toFixed(0)} FCFA
- Nombre de commandes : ${Number(orderCount || 0)}
- Panier moyen : ${avgOrder.toFixed(0)} FCFA
- Note moyenne de la boutique : ${storeRating || 0}/5
- Taux de fidÃ©litÃ© (clients qui ont achetÃ© plusieurs fois) : ${Number(fidelity || 0).toFixed(0)}%
- Nombre d'articles vendus : ${Number(totalItemsSold || 0)}
- CatÃ©gorie la plus vendue : ${topCategoryName || ''} (${Number(topCategoryCount || 0)} articles)
- Nombre de clients acquis (normalisÃ©) : ${Number(acquisition || 0).toFixed(0)}%

Donne 3 Ã  5 conseils personnalisÃ©s pour amÃ©liorer les ventes.`;

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
      const filteredHistory = history
        .filter(h => h.role === 'user' || h.role === 'assistant')
        .slice(-8); // keep last 8
        
      safeHistory = await Promise.all(filteredHistory.map(async msg => {
          let content = msg.content || '';
          if (Array.isArray(content)) {
            content = await Promise.all(content.map(async block => {
              if (block && block.type === 'cloudinary_image' && block.public_id) {
                const pid = block.public_id;
                
                // 1. Validation stricte et anti-path-traversal
                if (typeof pid !== 'string') {
                  const err = new Error('INVALID_MEDIA_REFERENCE'); err.statusCode = 400; throw err;
                }
                if (pid.includes('..') || pid.includes('//') || pid.includes('\\') || pid.includes('./')) {
                  const err = new Error('INVALID_MEDIA_PATH'); err.statusCode = 400; throw err;
                }
                
                const prefixEco = `chat_media/ecommerce/${uid}/`;
                const prefixRepos = `chat_media/repos/${uid}/`;
                
                if (!pid.startsWith(prefixEco) && !pid.startsWith(prefixRepos)) {
                  console.error(`Tentative d'accÃ¨s non autorisÃ© au media ${pid} par l'UID ${uid}`);
                  const err = new Error('UNAUTHORIZED_MEDIA'); err.statusCode = 403; throw err;
                }
                
                const assetPart = pid.startsWith(prefixEco) ? pid.substring(prefixEco.length) : pid.substring(prefixRepos.length);
                if (!assetPart || assetPart.trim() === '' || assetPart.includes('/')) {
                  const err = new Error('INVALID_ASSET_NAME'); err.statusCode = 400; throw err;
                }

                // 2. Fetch sÃ©curisÃ© et gestion des erreurs Cloudinary (Fail-Closed sans falsifier le prompt)
                try {
                  const url = cloudinary.url(pid, {
                    type: 'authenticated',
                    secure: true,
                    sign_url: true,
                  });
                  const imgRes = await fetch(url);
                  if (!imgRes.ok) {
                    console.error(`Cloudinary fetch error: ${imgRes.status}`);
                    const err = new Error('MEDIA_UNAVAILABLE');
                    err.statusCode = imgRes.status === 404 ? 404 : 502;
                    throw err;
                  }
                  const buffer = await imgRes.arrayBuffer();
                  const base64Image = Buffer.from(buffer).toString('base64');
                  
                  let mimeType = 'image/jpeg';
                  if (pid.toLowerCase().endsWith('.png')) mimeType = 'image/png';
                  if (pid.toLowerCase().endsWith('.gif')) mimeType = 'image/gif';
                  
                  return {
                    type: 'image_url',
                    image_url: { url: `data:${mimeType};base64,${base64Image}` }
                  };
                } catch (imgError) {
                  console.error('Cloudinary fetch exception:', imgError);
                  if (imgError.message === 'MEDIA_UNAVAILABLE') throw imgError;
                  const err = new Error('MEDIA_UNAVAILABLE');
                  err.statusCode = 502;
                  throw err;
                }
              }
              return block;
            }));
          }
          return {
            role: msg.role,
            content
          };
        }));
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
            suggestion: 'CrÃ©er une promotion ciblÃ©e (-15%)'
          });
        }
      } else if (salesLast30Days >= 10) {
        smartPricing.push({
          productId: doc.id,
          productName: name,
          reason: `Produit trÃ¨s demandÃ© (${salesLast30Days} ventes ces 30 derniers jours)`,
          suggestion: 'Augmenter lÃ©gÃ¨rement le prix (+5%)'
        });
      }
    }

    const recentReviews = reviewsSnap.docs.map(doc => `- ${doc.data().rating}/5: ${doc.data().comment || 'Pas de commentaire'}`).join("\n") || "Aucun avis";
    
    const recentOrders = recentOrdersDocs.map(doc => {
      const data = doc.data();
      return `- Commande ID=${doc.id}, Client=${data.customerName || 'Inconnu'}, Total=${Number(data.totalAmount)||0} CFA, Statut=${data.status||'pending'}, Livreur=${data.livreurName||'Non assignÃ©'}`;
    }).join("\n");

    const actualDrivers = driversSnap.empty ? driversBySellerSnap.docs : driversSnap.docs;
    const availableDrivers = actualDrivers.map(doc => {
      const data = doc.data();
      return `- ${data.name || 'Inconnu'} : ID=${doc.id}, Statut=${data.driverStatus || 'disponible'}, Zones=${data.coverageCommunes || []}`;
    }).join("\n");

    const storeContext = `CONTEXTE BOUTIQUE :
- Nom : ${storeData.storeName || 'Ma Boutique'}
- CatÃ©gorie : ${storeData.category || 'GÃ©nÃ©ral'}
- Ville : ${storeData.commune || 'Non spÃ©cifiÃ©e'}
- Note : ${Number(storeData.averageRating)||0}/5 (${Number(storeData.reviewCount)||0} avis)

PERFORMANCES GLOBALES (30 JOURS) :
- CA Total : ${totalRevenue.toFixed(0)} CFA
- Commandes : ${totalOrders}

CATALOGUE DÃ‰TAILLÃ‰ (Prix, Stocks et Ventes) :
${detailedProducts.map(p => `- ${p.nom} : ID=${p.id}, Prix=${p.prix} CFA, Stock=${p.stock_actuel}, Ventes=${p.ventes_30j}, CA=${p.ca_30j} CFA`).join("\n")}

COMMANDES RÃ‰CENTES (10 derniÃ¨res) :
${recentOrders}

LISTE DES LIVREURS :
${availableDrivers}

AVIS RÃ‰CENTS :
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
    } else if (language === "EspaÃ±ol") {
      systemPrompt = `Eres Repos, el asistente de comercio electrÃ³nico autÃ³nomo y proactivo de W-COM.
[DATOS DE TIENDA]
${storeContext}
[INFORMACIÃ“N INTELIGENTE (JSON)]
${insightsText}
TUS NUEVAS CAPACIDADES AUTÃ“NOMAS:
1. PrevisiÃ³n de stock: Analiza 'stockAlerts' para prevenir la falta de stock.
2. Smart Pricing: Utiliza 'smartPricing' para sugerir promociones dirigidas en inventario inactivo o sugerir aumentar los precios ligeramente.
3. Briefing: Utiliza 'dailyBriefing' para resumir el rendimiento.
4. CampaÃ±a de Marketing: Analiza 'inactiveClientsCount'. Si > 0, propone proactivamente enviar una campaÃ±a.
5. ACCIONES DE EDICIÃ“N (MUY IMPORTANTE):
   Utiliza el formato especial [ACTION:TYPE:ID:VALUE] en tu respuesta para activar la ejecuciÃ³n:
   - Precio: [ACTION:UPDATE_PRICE:productId:nuevo_precio]
   - Stock: [ACTION:UPDATE_STOCK:productId:nuevo_stock]
   - DescripciÃ³n: [ACTION:UPDATE_DESC:productId:nueva_descripcion]
   - Estado del pedido: [ACTION:UPDATE_ORDER_STATUS:orderId:nuevo_estado]
   - Asignar repartidor: [ACTION:ASSIGN_DRIVER:orderId:driverId:nombreRepartidor]
   - Enviar campaÃ±a: [ACTION:SEND_CAMPAIGN:descuento:cÃ³digoPromo]
REGLAS:
- SÃ© PROACTIVO. Si ves una alerta, menciÃ³nala.
- Responde siempre en EspaÃ±ol.`;
    } else {
      systemPrompt = `Tu es Repos, l'assistant e-commerce autonome et proactif de W-COM.
[DONNÃ‰ES BOUTIQUE]
${storeContext}
[INSIGHTS INTELLIGENTS (JSON)]
${insightsText}
TES NOUVELLES CAPACITÃ‰S AUTONOMES :
1. PrÃ©vision de stock : Analyse 'stockAlerts' pour prÃ©venir des ruptures.
2. Smart Pricing : Utilise 'smartPricing' pour suggÃ©rer de crÃ©er des promotions sur les stocks dormants ou d'augmenter le prix.
3. Briefing : Utilise 'dailyBriefing'.
4. Campagne Marketing : Analyse 'inactiveClientsCount'. Si > 0, propose d'envoyer une campagne.
5. ACTIONS DE MODIFICATION (TRÃˆS IMPORTANT) :
   Utilise le format [ACTION:TYPE:ID:VALEUR] dans ta rÃ©ponse :
   - Prix : [ACTION:UPDATE_PRICE:productId:nouveau_prix]
   - Stock : [ACTION:UPDATE_STOCK:productId:nouveau_stock]
   - Description : [ACTION:UPDATE_DESC:productId:nouvelle_description]
   - Statut Commande : [ACTION:UPDATE_ORDER_STATUS:orderId:nouveau_statut]
   - Assigner Livreur : [ACTION:ASSIGN_DRIVER:orderId:driverId:nomLivreur]
   - Envoyer Campagne : [ACTION:SEND_CAMPAIGN:remise:codePromo]
RÃˆGLES :
- Sois PROACTIF.
- RÃ©ponds toujours en FranÃ§ais.`;
    }

    const messagesForApi = [
      { role: "system", content: systemPrompt },
      ...safeHistory
    ];

    if (image && typeof image === 'string' && image.length < 5000000) {
       messagesForApi.push({
         role: "user",
         content: [
           { type: "text", text: (language === "English" ? "Here is the image to analyze:" : "Voici l'image Ã  analyser :") },
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

        if (language && (language.toLowerCase().startsWith('fran') || language.toLowerCase() === 'french')) language = 'French';
    if (language && (language.toLowerCase().startsWith('anglais') || language.toLowerCase() === 'english')) language = 'English';
    const ALLOWED_LANGUAGES = new Set(['French', 'English', 'EspaÃ±ol']);
    if (language == null) {
      language = 'French';
    } else if (!ALLOWED_LANGUAGES.has(language) && language !== 'EspaÃ±ol' && !language.startsWith('Espa')) {
      return res.status(400).json({ error: 'invalid language' });
    }
    if (language && language.startsWith('Espa')) language = 'EspaÃ±ol';

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
      } else if (language === 'EspaÃ±ol') {
        systemPrompt = "Eres un asistente de comercio electrÃ³nico que escribe descripciones de productos precisas, naturales y Ãºtiles.";
        userPrompt = `Redacta una descripciÃ³n de producto atractiva en espaÃ±ol para un mercado marfileÃ±o.\nProducto: ${safeName}\nCategorÃ­a: ${safeCategory}\nPrecio: ${safePrice}\nStock: ${safeStock || 'no especificado'}\nRestricciones: 70 a 110 palabras, tono profesional y cÃ¡lido, sin emojis, sin promesas imposibles, termina con una llamada a la acciÃ³n corta.`;
      } else {
        systemPrompt = "Tu es un assistant e-commerce qui Ã©crit des descriptions produit prÃ©cises, naturelles et utiles.";
        userPrompt = `RÃ©dige une description produit vendeuse en franÃ§ais pour une marketplace ivoirienne.\nProduit: ${safeName}\nCatÃ©gorie: ${safeCategory}\nPrix: ${safePrice}\nStock: ${safeStock || 'non prÃ©cisÃ©'}\nContraintes: 70 Ã  110 mots, ton professionnel et chaleureux, pas d'emojis, pas de promesses impossibles, termine par un appel Ã  l'action court.`;
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

      const noDescText = language === 'English' ? 'No description' : (language === 'EspaÃ±ol' ? 'Sin descripciÃ³n' : 'Pas de description');
      const productsInfoList = productDocs.map(doc => {
        const p = doc.data();
        const priceCfa = p.price != null ? `${p.price} CFA` : '';
        const desc = p.description ? p.description : noDescText;
        return `- ${p.name || 'Produit'} (${priceCfa}) : ${desc}`;
      }).join('\n');

      if (language === 'English') {
        systemPrompt = "You are a renowned e-commerce literary writer (named Repos) specialized in storytelling for fashion and craft collections.";
        userPrompt = `Write a captivating and immersive narrative story in English to present these products in a Lookbook / Fashion-Beauty-Style Editorial.\nProducts:\n${productsInfoList}\n\nConstraints:\n- Length: 150 to 250 words.\n- Immersive and poetic tone, like a creator's blog or a Wattpad chapter.\n- No emojis, weave in beautiful metaphors around these pieces.\n- Make clear paragraphs separated by line breaks.`;
      } else if (language === 'EspaÃ±ol') {
        systemPrompt = "Eres un reconocido escritor literario de comercio electrÃ³nico (llamado Repos) especializado en storytelling de colecciones de moda y artesanÃ­a.";
        userPrompt = `Redacta una historia narrativa cautivadora e inmersiva en espaÃ±ol para presentar estos productos en un Lookbook / Editorial de moda/belleza/estilo.\nProductos:\n${productsInfoList}\n\nRestricciones:\n- Longitud: 150 a 250 palabras.\n- Tono inmersivo y poÃ©tico, tipo blog de creador o capÃ­tulo de Wattpad.\n- Sin emojis, incorpora hermosas metÃ¡foras alrededor de estas piezas.\n- Haz pÃ¡rrafos claros separados por saltos de lÃ­nea.`;
      } else {
        systemPrompt = "Tu es un rÃ©dacteur littÃ©raire e-commerce de renom (nommÃ© Repos) spÃ©cialisÃ© dans le storytelling de collections de mode et d'artisanat.";
        userPrompt = `RÃ©dige une histoire narrative captivante et immersive en franÃ§ais pour prÃ©senter ces produits dans un Lookbook / Ã‰ditorial de mode/beautÃ©/style.\nProduits :\n${productsInfoList}\n\nContraintes :\n- Longueur: 150 Ã  250 mots.\n- Ton immersif et poÃ©tique, type blog de crÃ©ateur ou chapitre Wattpad.\n- Pas d'emojis, intÃ¨gre de magnifiques mÃ©taphores autour de ces piÃ¨ces.\n- Fais des paragraphes clairs espacÃ©s par des sauts de ligne.`;
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
// Endpoint dï¿½diï¿½ spï¿½cifique pour le Marketing (Phase 1G.4.2)
// Sï¿½curisï¿½ : Authentification, Validation stricte des inputs, Modï¿½le et Prompt serveur
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
    
    if (!['French', 'English', 'Espaï¿½ol'].includes(language)) {
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
      } else if (language === 'Espaï¿½ol') {
        systemPrompt = `Eres un experto en marketing digital para el comercio electrï¿½nico en Costa de Marfil.\nGenera 3 variantes de captions para ${platform} con el tono "${safeTone}".`;
        if (platform.toLowerCase().includes('whatsapp status') || platform.toLowerCase() === 'whatsapp') {
          systemPrompt = `Eres un experto en marketing digital para el comercio electrï¿½nico en Costa de Marfil.\nGenera 3 variantes de estado de WhatsApp con el tono "${safeTone}": una corta e impactante, una narrativa/emotiva, y una agresiva estilo venta flash.`;
        }
        userPrompt = `Producto: ${productName}\nUbicaciï¿½n: ${safeCity}\nOpciones: Emojis=${emojis}, Hashtags=${hashtags}, CTA=${cta}, Promo=${promo}, Ubicaciï¿½n=${location}\n\nResponde ï¿½NICAMENTE con un array JSON de 3 strings, uno por lï¿½nea, sin markdown.`;
      } else {
        systemPrompt = `Tu es un expert en marketing digital pour le e-commerce en Cï¿½te d'Ivoire.\nGï¿½nï¿½re 3 variantes de captions pour ${platform} avec le ton "${safeTone}".`;
        if (platform.toLowerCase().includes('whatsapp status') || platform.toLowerCase() === 'whatsapp') {
          systemPrompt = `Tu es un expert en marketing digital pour le e-commerce en Cï¿½te d'Ivoire.\nGï¿½nï¿½re 3 variantes de statut WhatsApp avec le ton "${safeTone}" : une courte et percutante, une storytelling/ï¿½motive, une agressive style vente flash.`;
        }
        userPrompt = `Produit : ${productName}\nLocalisation : ${safeCity}\nOptions : Emojis=${emojis}, Hashtags=${hashtags}, CTA=${cta}, Promo=${promo}, Mention localisation=${location}\n\nRï¿½ponds UNIQUEMENT avec un JSON array de 3 strings, une par ligne, sans markdown.`;
      }

    } else if (operation === 'campaign') {
      const { channel, campaignName, productNames } = req.body;
      
      if (typeof channel !== 'string' || channel.length > 50) return res.status(400).json({ error: 'invalid_channel' });
      if (typeof campaignName !== 'string' || campaignName.length > 100) return res.status(400).json({ error: 'invalid_campaignName' });
      
      const safeProductNames = (typeof productNames === 'string') ? productNames.substring(0, 300) : 'divers produits';
      const ctaWhatsAppFr = channel.toLowerCase() === 'whatsapp' ? "Inclus un appel ï¿½ l'action pour contacter le vendeur et commander." : "";
      const ctaWhatsAppEn = channel.toLowerCase() === 'whatsapp' ? "Include a call to action to contact the seller and order." : "";
      const ctaWhatsAppEs = channel.toLowerCase() === 'whatsapp' ? "Incluye una llamada a la acciï¿½n para escribir al vendedor y pedir." : "";
      
      if (language === 'English') {
        systemPrompt = `You are a digital marketing expert for e-commerce in Ivory Coast.\nGenerate 3 short variants of marketing messages for a "${channel}" campaign named "${campaignName}".`;
        userPrompt = `Featured products: ${safeProductNames}\n${ctaWhatsAppEn}\n\nRespond ONLY with a JSON array of 3 strings, without markdown.`;
      } else if (language === 'Espaï¿½ol') {
        systemPrompt = `Eres un experto en marketing digital para el comercio electrï¿½nico en Costa de Marfil.\nGenera 3 variantes cortas de mensajes de marketing para una campaï¿½a "${channel}" llamada "${campaignName}".`;
        userPrompt = `Productos destacados: ${safeProductNames}\n${ctaWhatsAppEs}\n\nResponde ï¿½NICAMENTE con un array JSON de 3 strings, sin markdown.`;
      } else {
        systemPrompt = `Tu es un expert en marketing digital pour le e-commerce en Cï¿½te d'Ivoire.\nGï¿½nï¿½re 3 variantes courtes de messages marketing pour une campagne "${channel}" nommï¿½e "${campaignName}".`;
        userPrompt = `Produits mis en avant : ${safeProductNames}\n${ctaWhatsAppFr}\n\nRï¿½ponds UNIQUEMENT avec un JSON array de 3 strings, sans markdown.`;
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

        if (language && (language.toLowerCase().startsWith('fran') || language.toLowerCase() === 'french')) language = 'French';
    if (language && (language.toLowerCase().startsWith('anglais') || language.toLowerCase() === 'english')) language = 'English';
    const ALLOWED_LANGUAGES = new Set(['French', 'English', 'EspaÃ±ol']);
    if (language == null) {
      language = 'French';
    } else if (!ALLOWED_LANGUAGES.has(language) && language !== 'EspaÃ±ol' && !language.startsWith('Espa')) {
      return res.status(400).json({ error: 'Invalid language' });
    }
    if (language && language.startsWith('Espa')) language = 'EspaÃ±ol';

    let systemPrompt = "";
    if (type === 'customer') {
      if (language === 'English') {
        systemPrompt = "You are the AI assistant of W-COM. Summarize this commercial conversation in 2 to 3 sentences. Highlight the main intent, important requests, and useful elements for the seller. Be factual and concise. Do not create any information not present in the conversation.";
      } else if (language === 'EspaÃ±ol') {
        systemPrompt = "Eres el asistente de IA de W-COM. Resume esta conversaciÃ³n comercial en 2 a 3 oraciones. Destaca la intenciÃ³n principal, las solicitudes importantes y los elementos Ãºtiles para el vendedor. SÃ© factual y conciso. No crees informaciÃ³n que no estÃ© en la conversaciÃ³n.";
      } else {
        systemPrompt = "Tu es l'assistant IA de W-COM. RÃ©sume cette conversation commerciale en 2 Ã  3 phrases. Mets en Ã©vidence l'intention principale, les demandes importantes et les Ã©lÃ©ments utiles pour le vendeur. Reste factuel et concis. Ne crÃ©e aucune information absente de la conversation.";
      }
    } else if (type === 'workspace') {
      if (language === 'English') {
        systemPrompt = "You are the AI assistant of W-COM Workspace. Summarize this professional conversation in 2 to 3 sentences. Highlight decisions, problems, important requests, and next actions when explicitly present. Be factual and concise. Do not create any information not present in the conversation.";
      } else if (language === 'EspaÃ±ol') {
        systemPrompt = "Eres el asistente de IA de W-COM Workspace. Resume esta conversaciÃ³n profesional en 2 a 3 oraciones. Destaca decisiones, problemas, solicitudes importantes y prÃ³ximos pasos cuando estÃ©n explÃ­citamente presentes. SÃ© factual y conciso. No crees informaciÃ³n que no estÃ© en la conversaciÃ³n.";
      } else {
        systemPrompt = "Tu es l'assistant IA de W-COM Workspace. RÃ©sume cette conversation professionnelle en 2 Ã  3 phrases. Mets en Ã©vidence les dÃ©cisions, problÃ¨mes, demandes importantes et prochaines actions lorsqu'elles sont explicitement prÃ©sentes. Reste factuel et concis. Ne crÃ©e aucune information absente de la conversation.";
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
const riskAlertRateLimits = new Map();

// Helper geographique (Haversine)
function getDistanceMeters(lat1, lon1, lat2, lon2) {
  const R = 6371e3; // metres
  const dLat = (lat2 - lat1) * Math.PI / 180;
  const dLon = (lon2 - lon1) * Math.PI / 180;
  const a = Math.sin(dLat / 2) * Math.sin(dLat / 2) +
            Math.cos(lat1 * Math.PI / 180) * Math.cos(lat2 * Math.PI / 180) *
            Math.sin(dLon / 2) * Math.sin(dLon / 2);
  const c = 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1 - a));
  return R * c;
}


// ============================================================
// PHASE 2.2.1-B-C7-C7-D : GET /api/drivers/nearby
// Remplacement du calcul GPS local Flutter. Expose uniquement
// les donnees operationnelles (driver_availability) et calcule
// la distance serveur via le GPS prive (public_drivers).
// ============================================================
const nearbyDriversRateLimits = new Map();

app.get('/api/drivers/nearby', async (req, res) => {
  try {
    const decoded = await requireAuth(req);
    const uid = decoded.uid;

    // Rate Limit: 20 requetes / minute / UID
    const now = Date.now();
    const rateData = nearbyDriversRateLimits.get(uid) || { count: 0, resetTime: now + 60000 };
    if (now > rateData.resetTime) {
      rateData.count = 0;
      rateData.resetTime = now + 60000;
    }
    rateData.count++;
    nearbyDriversRateLimits.set(uid, rateData);

    if (rateData.count > 20) {
      return res.status(429).json({ error: 'rate_limit_exceeded', message: 'Too many nearby requests' });
    }

    // 1. Validation des parametres
    // Par defaut: centre d'Abidjan (comportement routes_screen.dart actuel)
    const lat = req.query.lat !== undefined ? parseFloat(req.query.lat) : 5.3600;
    const lng = req.query.lng !== undefined ? parseFloat(req.query.lng) : -4.0083;
    const radiusKm = req.query.radiusKm !== undefined ? parseFloat(req.query.radiusKm) : 5;

    if (!Number.isFinite(lat) || lat < -90 || lat > 90) {
      return res.status(400).json({ error: 'invalid_lat' });
    }
    if (!Number.isFinite(lng) || lng < -180 || lng > 180) {
      return res.status(400).json({ error: 'invalid_lng' });
    }
    if (!Number.isFinite(radiusKm) || radiusKm <= 0 || radiusKm > 10) {
      return res.status(400).json({ error: 'invalid_radius' });
    }

    // 2. Source OpArationnelle: driver_availability
    const availabilitySnap = await db.collection('driver_availability')
      .where('isAvailable', '==', true)
      .where('status', '==', 'active')
      .get();

    const operationalDrivers = [];
    availabilitySnap.forEach(doc => {
      operationalDrivers.push({ id: doc.id, ...doc.data() });
    });

    if (operationalDrivers.length === 0) {
      return res.status(200).json({ drivers: [] });
    }

    // 3. RAccupAcration GPS Prive (server-side ONLY)
    // Chunking par 30 pour la limite Firestore de whereIn
    const gpsDataMap = new Map();
    const uids = operationalDrivers.map(d => d.id);
    
    for (let i = 0; i < uids.length; i += 30) {
      const chunk = uids.slice(i, i + 30);
      const gpsSnap = await db.collection('public_drivers')
        .where('__name__', 'in', chunk)
        .get();
        
      gpsSnap.forEach(doc => {
        const data = doc.data();
        if (
          typeof data.lastLat === 'number' && typeof data.lastLng === 'number' &&
          Number.isFinite(data.lastLat) && Number.isFinite(data.lastLng) &&
          data.lastLat >= -90 && data.lastLat <= 90 &&
          data.lastLng >= -180 && data.lastLng <= 180 &&
          !(data.lastLat === 0 && data.lastLng === 0)
        ) {
          gpsDataMap.set(doc.id, { lat: data.lastLat, lng: data.lastLng });
        }
      });
    }

    // 4. Calcul Haversine, Filtrage et Tri
    const driversWithDistance = [];
    for (const driver of operationalDrivers) {
      const gps = gpsDataMap.get(driver.id);
      if (!gps) continue;

      const distanceMeters = getDistanceMeters(lat, lng, gps.lat, gps.lng);
      const distanceKm = distanceMeters / 1000;

      if (distanceKm <= radiusKm) {
        const responseDriver = {
          userId: driver.userId || driver.id,
          name: driver.name || 'Livreur',
          vehicleType: driver.vehicleType || 'moto',
          status: driver.status || 'available',
          isAvailable: driver.isAvailable === true,
          distanceKm: Math.round(distanceKm * 10) / 10 // Arrondi a 1 decimale
        };
        
        if (driver.averageRating !== undefined) {
          responseDriver.averageRating = driver.averageRating;
        }
        if (driver.ratingCount !== undefined) {
          responseDriver.ratingCount = driver.ratingCount;
        }

        driversWithDistance.push(responseDriver);
      }
    }

    driversWithDistance.sort((a, b) => a.distanceKm - b.distanceKm);

    // 5. Maximum 3 rAcsultats (C7-C7 limitation)
    const finalDrivers = driversWithDistance.slice(0, 3);

    return res.status(200).json({ drivers: finalDrivers });

  } catch (error) {
    console.error('Error in /api/drivers/nearby:', error);
    return res.status(500).json({ error: 'internal_error' });
  }
});


// ============================================================
// PHASE 2.2.1-B-C7-C7-H : POST /api/drivers/contact-request
// Premier contact vers un livreur public sans exposer de PII.
// ============================================================
const driverContactRateLimits = new Map();

app.post('/api/drivers/contact-request', async (req, res) => {
  try {
    const decoded = await requireAuth(req);
    const sellerUid = decoded.uid;

    if (!db) return res.status(503).json({ error: 'firestore not configured' });

    // 1. Validation du payload (RESTRICTIF)
    const { driverId, message } = req.body || {};
    
    if (!driverId || typeof driverId !== 'string' || driverId.trim() === '' || driverId.length > 128) {
      return res.status(400).json({ error: 'INVALID_DRIVER_ID' });
    }
    if (driverId.includes('/') || driverId.includes('..')) {
      return res.status(400).json({ error: 'INVALID_DRIVER_ID_FORMAT' });
    }

    if (!message || typeof message !== 'string' || message.trim() === '') {
      return res.status(400).json({ error: 'INVALID_MESSAGE' });
    }
    
    const cleanMessage = message.trim();
    if (cleanMessage.length > 140) {
      return res.status(400).json({ error: 'MESSAGE_TOO_LONG' });
    }

    // 2. Verification anti-spam (Vendeur : max 10/24h)
    const now = Date.now();
    let sellerRate = driverContactRateLimits.get(sellerUid) || { count: 0, resetTime: now + 24 * 60 * 60 * 1000 };
    if (now > sellerRate.resetTime) {
      sellerRate.count = 0;
      sellerRate.resetTime = now + 24 * 60 * 60 * 1000;
    }
    if (sellerRate.count >= 10) {
      return res.status(429).json({ error: 'SELLER_RATE_LIMIT_EXCEEDED' });
    }

    // 3. Verification de la disponibilite du livreur (driver_availability)
    const availabilityRef = db.collection('driver_availability').doc(driverId);
    const availabilitySnap = await availabilityRef.get();
    
    if (!availabilitySnap.exists) {
      return res.status(404).json({ error: 'DRIVER_NOT_FOUND' });
    }
    
    const availabilityData = availabilitySnap.data();
    if (
      availabilityData.userId !== driverId || 
      availabilityData.isAvailable !== true || 
      availabilityData.status !== 'active'
    ) {
      return res.status(403).json({ error: 'DRIVER_NOT_AVAILABLE' });
    }

    // 4. Verification de l'identite du vendeur et du telephone (stores)
    const storesSnap = await db.collection('stores')
      .where('ownerId', '==', sellerUid)
      .limit(1)
      .get();
      
    if (storesSnap.empty) {
      return res.status(403).json({ error: 'SELLER_STORE_NOT_FOUND' });
    }
    
    const storeDoc = storesSnap.docs[0];
    const storeData = storeDoc.data();
    const sellerPhone = storeData.phone;
    const storeName = storeData.storeName || 'Vendeur W-Com';
    
    if (!sellerPhone || typeof sellerPhone !== 'string' || sellerPhone.trim() === '') {
      return res.status(403).json({ error: 'SELLER_PHONE_MISSING' });
    }

    // 5. Verification de la relation et des cooldowns
    const requestId = `${sellerUid}_${driverId}`;
    const requestRef = db.collection('driver_contact_requests').doc(requestId);
    const requestSnap = await requestRef.get();
    
    if (requestSnap.exists) {
      const data = requestSnap.data();
      const expiresAt = data.expiresAt ? data.expiresAt.toDate() : 0;
      
      if (data.status === 'pending' && expiresAt > new Date()) {
        return res.status(409).json({ error: 'CONTACT_REQUEST_ALREADY_PENDING' });
      }
      
      if (data.status === 'accepted') {
        return res.status(409).json({ error: 'RELATION_ALREADY_EXISTS' });
      }
      
      if (data.status === 'declined' && data.declinedAt) {
        const thirtyDaysAgo = new Date(Date.now() - 30 * 24 * 60 * 60 * 1000);
        if (data.declinedAt.toDate() > thirtyDaysAgo) {
          return res.status(429).json({ error: 'DECLINED_COOLDOWN_ACTIVE' });
        }
      }
    }

    // 6. Anti-spam Livreur (max 5 pending)
    const pendingSnap = await db.collection('driver_contact_requests')
      .where('driverId', '==', driverId)
      .where('status', '==', 'pending')
      .get();
      
    let activePendingCount = 0;
    pendingSnap.forEach(doc => {
      const data = doc.data();
      if (data.expiresAt && data.expiresAt.toDate() > new Date()) {
        activePendingCount++;
      }
    });
    
    if (activePendingCount >= 5) {
      return res.status(429).json({ error: 'DRIVER_INBOX_FULL' });
    }

    // 7. Creation de la requete de contact Firestore
    const expiresDate = new Date(Date.now() + 24 * 60 * 60 * 1000);
    
    await requestRef.set({
      sellerId: sellerUid,
      storeId: storeDoc.id,
      storeName: storeName,
      driverId: driverId,
      status: 'pending',
      message: cleanMessage,
      createdAt: admin.firestore.FieldValue.serverTimestamp(),
      expiresAt: admin.firestore.Timestamp.fromDate(expiresDate),
      pushStatus: 'pending'
    });

    // Incrementer le rate limit vendeur car la requete Firestore est enregistree
    sellerRate.count++;
    driverContactRateLimits.set(sellerUid, sellerRate);

    // 8. Envoi de la notification Push
    const cleanPhone = sellerPhone.replace(/\D/g, '');
    const whatsappUrl = `https://wa.me/${cleanPhone}`;
    const pushPrefix = `Demande de ${storeName} : `;
    
    const payload = {
      app_id: ONESIGNAL_APP_ID,
      include_aliases: {
        external_id: [driverId]
      },
      target_channel: "push",
      headings: {
        en: "Nouvelle demande de livraison",
        fr: "Nouvelle demande de livraison"
      },
      contents: {
        en: pushPrefix + cleanMessage,
        fr: pushPrefix + cleanMessage
      },
      url: whatsappUrl
    };

    if (process.env.ONESIGNAL_REST_API_KEY) {
      try {
        const osResponse = await fetch('https://onesignal.com/api/v1/notifications', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json; charset=utf-8',
            Authorization: `Basic ${process.env.ONESIGNAL_REST_API_KEY}`,
          },
          body: JSON.stringify(payload),
        });

        if (osResponse.ok) {
          await requestRef.update({ pushStatus: 'sent' });
        } else {
          await requestRef.update({ pushStatus: 'failed' });
          console.error('OneSignal failed for contact request', await osResponse.text());
        }
      } catch (e) {
        await requestRef.update({ pushStatus: 'error' });
        console.error('OneSignal network error for contact request', e.message);
      }
    } else {
        await requestRef.update({ pushStatus: 'onesignal_not_configured' });
    }

    // Ne renvoie aucune donnee privee du livreur
    return res.status(201).json({ success: true, status: 'pending' });

  } catch (error) {
    if (error.statusCode === 401) {
      return res.status(401).json({ error: 'unauthorized' });
    }
    console.error('Error in /api/drivers/contact-request:', error);
    return res.status(500).json({ error: 'internal_error' });
  }
});


// ============================================================
// PHASE 2.2.1-B-C7-C7-J : POST /api/drivers/traffic-alert
// Broadcast d'alerte trafic aux livreurs publics proches (5km)
// sans texte libre et sans controle OneSignal par le client.
// ============================================================
const trafficAlertRateLimits = new Map();
const trafficAlertZoneCooldowns = []; // Simple in-memory zone cooldown array

app.post('/api/drivers/traffic-alert', async (req, res) => {
  try {
    const decoded = await requireAuth(req);
    const sellerUid = decoded.uid;

    if (!db) return res.status(503).json({ error: 'firestore not configured' });

    // 1. Validation GPS (seules donnees acceptees)
    const { lat, lng } = req.body || {};
    
    if (typeof lat !== 'number' || typeof lng !== 'number') {
      return res.status(400).json({ error: 'INVALID_COORDINATES' });
    }
    if (!Number.isFinite(lat) || lat < -90 || lat > 90) {
      return res.status(400).json({ error: 'INVALID_LATITUDE' });
    }
    if (!Number.isFinite(lng) || lng < -180 || lng > 180) {
      return res.status(400).json({ error: 'INVALID_LONGITUDE' });
    }

    // 2. Rate Limit Vendeur (1 alerte / 15 minutes)
    const now = Date.now();
    const rateData = trafficAlertRateLimits.get(sellerUid) || { resetTime: 0 };
    if (now < rateData.resetTime) {
      return res.status(429).json({ error: 'RATE_LIMIT_EXCEEDED' });
    }
    
    // Cooldown Zone (optionnel, memoire uniquement, 10 min, rayon 2km par ex)
    const recentZoneAlerts = trafficAlertZoneCooldowns.filter(a => now < a.expiresAt);
    // Nettoyage en passant
    trafficAlertZoneCooldowns.length = 0;
    trafficAlertZoneCooldowns.push(...recentZoneAlerts);
    
    for (const alert of recentZoneAlerts) {
      const dist = getDistanceMeters(lat, lng, alert.lat, alert.lng);
      if (dist < 2000) { // 2km radius pour eviter les doublons
        return res.status(429).json({ error: 'ZONE_COOLDOWN_ACTIVE' });
      }
    }

    // 3. Source OpArationnelle: driver_availability
    const availabilitySnap = await db.collection('driver_availability')
      .where('isAvailable', '==', true)
      .where('status', '==', 'active')
      .get();

    const operationalDrivers = [];
    availabilitySnap.forEach(doc => {
      // Exclure le vendeur lui-meme s'il est aussi livreur
      if (doc.id !== sellerUid && doc.data().userId !== sellerUid) {
        operationalDrivers.push(doc.id);
      }
    });

    if (operationalDrivers.length === 0) {
      // Marquer le rate limit meme si aucun livreur
      trafficAlertRateLimits.set(sellerUid, { resetTime: now + 15 * 60 * 1000 });
      return res.status(200).json({ success: true, count: 0 });
    }

    // 4. RAccupAcration GPS Prive (server-side ONLY) & Haversine
    const nearbyDriverIds = [];
    
    for (let i = 0; i < operationalDrivers.length; i += 30) {
      const chunk = operationalDrivers.slice(i, i + 30);
      const gpsSnap = await db.collection('public_drivers')
        .where('__name__', 'in', chunk)
        .get();
        
      gpsSnap.forEach(doc => {
        const data = doc.data();
        if (
          typeof data.lastLat === 'number' && typeof data.lastLng === 'number' &&
          Number.isFinite(data.lastLat) && Number.isFinite(data.lastLng) &&
          !(data.lastLat === 0 && data.lastLng === 0)
        ) {
          const distanceMeters = getDistanceMeters(lat, lng, data.lastLat, data.lastLng);
          if (distanceMeters <= 5000) { // Rayon forcAc: 5km
            nearbyDriverIds.push({ id: doc.id, distance: distanceMeters });
          }
        }
      });
    }

    // Tri par distance et max 30
    nearbyDriverIds.sort((a, b) => a.distance - b.distance);
    const selectedDriverIds = nearbyDriverIds.slice(0, 30).map(d => d.id);

    // Mettre a jour les rate limits (seulement si on envoie vraiment ou si on a essaye)
    trafficAlertRateLimits.set(sellerUid, { resetTime: now + 15 * 60 * 1000 });
    trafficAlertZoneCooldowns.push({ lat, lng, expiresAt: now + 10 * 60 * 1000 });

    if (selectedDriverIds.length === 0) {
      return res.status(200).json({ success: true, count: 0 });
    }

    // 5. Envoi Push OneSignal Server-Controlled
    if (process.env.ONESIGNAL_REST_API_KEY && process.env.ONESIGNAL_APP_ID) {
      const payload = {
        app_id: process.env.ONESIGNAL_APP_ID,
        include_aliases: {
          external_id: selectedDriverIds
        },
        target_channel: "push",
        headings: {
          en: "Traffic Alert",
          fr: "Alerte Trafic"
        },
        contents: {
          en: "A traffic alert has been reported near your location.",
          fr: "Une alerte trafic a A(c)tA(c) signalA(c)e A  proximitA(c) de votre position."
        }
      };

      try {
        await fetch('https://onesignal.com/api/v1/notifications', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json; charset=utf-8',
            Authorization: `Basic ${process.env.ONESIGNAL_REST_API_KEY}`,
          },
          body: JSON.stringify(payload),
        });
        // Ignore response errors for broadcast, don't expose them
      } catch (e) {
        console.error('OneSignal network error for traffic alert', e.message);
      }
    }

    return res.status(200).json({ success: true });

  } catch (error) {
    if (error.statusCode === 401) {
      return res.status(401).json({ error: 'unauthorized' });
    }
    console.error('Error in /api/drivers/traffic-alert:', error);
    return res.status(500).json({ error: 'internal_error' });
  }
});


// ============================================================
// PHASE 2.2.1-B-C7-C7-M : POST /api/drivers/rate
// ============================================================
app.post('/api/drivers/rate', async (req, res) => {
  try {
    const decoded = await requireAuth(req);
    const buyerUid = decoded.uid;

    if (!db) return res.status(503).json({ error: 'firestore not configured' });

    const { orderId, driverId, rating, comment = '' } = req.body || {};

    if (!orderId || typeof orderId !== 'string') {
      return res.status(400).json({ error: 'INVALID_ORDER_ID' });
    }
    if (!driverId || typeof driverId !== 'string') {
      return res.status(400).json({ error: 'INVALID_DRIVER_ID' });
    }
    if (typeof rating !== 'number' || rating < 1 || rating > 5 || !Number.isInteger(rating)) {
      return res.status(400).json({ error: 'INVALID_RATING' });
    }
    
    // Authorization & Idempotency in a Transaction
    await db.runTransaction(async (txn) => {
      // 1. Verifier l'idempotence (rating deja effectue pour cette commande ?)
      const ratingRef = db.collection('driver_ratings').doc(orderId);
      const existingRating = await txn.get(ratingRef);
      if (existingRating.exists) {
        throw new Error('ALREADY_RATED'); // Sera catche et retournera 409
      }

      // 2. Verifier l'autorisation via la commande
      const orderRef = db.collection('orders').doc(orderId);
      const orderSnap = await txn.get(orderRef);
      if (!orderSnap.exists) {
        throw new Error('ORDER_NOT_FOUND');
      }
      
      const order = orderSnap.data();
      if (order.buyerId !== buyerUid) {
        throw new Error('UNAUTHORIZED_BUYER');
      }
      if (order.status !== 'delivered') {
        throw new Error('ORDER_NOT_DELIVERED');
      }
      
      // Resolution du driverId reel (comme dans _resolvePublicDriverId de Flutter)
      const assignedDriverId = order.assignedDriverId;
      if (!assignedDriverId) {
        throw new Error('NO_DRIVER_ASSIGNED');
      }
      
      let resolvedDriverId = null;
      const publicDocSnap = await txn.get(db.collection('public_drivers').doc(assignedDriverId));
      if (publicDocSnap.exists) {
        resolvedDriverId = assignedDriverId;
      } else {
        const fleetDocSnap = await txn.get(db.collection('delivery_drivers').doc(assignedDriverId));
        if (fleetDocSnap.exists) {
          const linkedUserId = fleetDocSnap.data().userId;
          if (linkedUserId && typeof linkedUserId === 'string' && linkedUserId.trim() !== '') {
            resolvedDriverId = linkedUserId;
          }
        }
      }
      
      if (!resolvedDriverId) {
        throw new Error('DRIVER_NOT_RATABLE');
      }
      
      if (resolvedDriverId !== driverId) {
        // Le client essaie de noter un autre livreur que celui reellement assigne
        throw new Error('DRIVER_MISMATCH');
      }
      
      // 3. Lire le profil et calculer la moyenne
      const driverRef = db.collection('public_drivers').doc(resolvedDriverId);
      const driverSnap = await txn.get(driverRef);
      if (!driverSnap.exists) {
        throw new Error('DRIVER_NOT_FOUND');
      }
      
      const driverData = driverSnap.data();
      const oldAvg = typeof driverData.averageRating === 'number' ? driverData.averageRating : 0.0;
      const oldCount = typeof driverData.ratingCount === 'number' ? driverData.ratingCount : 0;
      
      const newCount = oldCount + 1;
      const newAvgRaw = oldCount === 0 ? rating : ((oldAvg * oldCount) + rating) / newCount;
      const newAvg = Number(newAvgRaw.toFixed(2));
      
      // 4. Ecriture (Rating, Public Profile, Availability)
      txn.set(ratingRef, {
        orderId: orderId,
        driverId: resolvedDriverId,
        buyerId: buyerUid,
        buyerName: decoded.name || decoded.email || 'Client',
        rating: rating,
        comment: typeof comment === 'string' ? comment.trim() : '',
        timestamp: require('firebase-admin').firestore.FieldValue.serverTimestamp(),
      });
      
      txn.update(driverRef, {
        averageRating: newAvg,
        ratingCount: newCount,
      });
      
      const availabilityRef = db.collection('driver_availability').doc(resolvedDriverId);
      txn.set(availabilityRef, {
        userId: resolvedDriverId,
        name: driverData.name || '',
        vehicleType: driverData.vehicleType || driverData.vehicle || '',
        status: driverData.status || 'active',
        isAvailable: driverData.isAvailable || false,
        averageRating: newAvg,
        ratingCount: newCount,
      }, { merge: true });
    });

    return res.status(200).json({ success: true });

  } catch (error) {
    if (error.statusCode === 401) {
      return res.status(401).json({ error: 'unauthorized' });
    }
    if (error.message === 'ALREADY_RATED') {
      return res.status(409).json({ error: 'ALREADY_RATED' });
    }
    if (error.message === 'UNAUTHORIZED_BUYER' || error.message === 'DRIVER_MISMATCH') {
      return res.status(403).json({ error: error.message });
    }
    if (error.message === 'ORDER_NOT_FOUND' || error.message === 'DRIVER_NOT_FOUND' || error.message === 'DRIVER_NOT_RATABLE') {
      return res.status(404).json({ error: error.message });
    }
    if (error.message === 'ORDER_NOT_DELIVERED' || error.message === 'NO_DRIVER_ASSIGNED') {
      return res.status(400).json({ error: error.message });
    }
    
    console.error('Error in /api/drivers/rate:', error);
    return res.status(500).json({ error: 'internal_error' });
  }
});

app.post('/api/risk/alert', async (req, res) => {
  try {
    const decoded = await requireAuth(req);
    const uid = decoded.uid;

    // Rate Limiting : 1 requete / 60s / UID (protection anti-spam niveau 1 en memoire)
    const now = Date.now();
    const rateData = riskAlertRateLimits.get(uid) || { count: 0, resetTime: now + 60000 };
    if (now > rateData.resetTime) {
      rateData.count = 0;
      rateData.resetTime = now + 60000;
    }
    rateData.count++;
    riskAlertRateLimits.set(uid, rateData);
    if (rateData.count > 1) {
      return res.status(429).json({ error: 'rate_limit_exceeded' });
    }

    // Validation du payload
    const { lat, lng, description } = req.body || {};
    
    if (typeof lat !== 'number' || !Number.isFinite(lat) || lat < -90 || lat > 90) {
      return res.status(400).json({ error: 'invalid_lat' });
    }
    if (typeof lng !== 'number' || !Number.isFinite(lng) || lng < -180 || lng > 180) {
      return res.status(400).json({ error: 'invalid_lng' });
    }
    
    if (typeof description !== 'string') {
      return res.status(400).json({ error: 'invalid_description' });
    }
    const trimmedDesc = description.trim();
    if (trimmedDesc.length === 0 || trimmedDesc.length > 500) {
      return res.status(400).json({ error: 'invalid_description' });
    }

    if (!db) {
      return res.status(500).json({ error: 'database_not_initialized' });
    }

    // Lecture Firestore (Admin SDK)
    const driversSnap = await db.collection('public_drivers')
      .where('isAvailable', '==', true)
      .where('status', '==', 'active')
      .get();

    const nearbyDriverIds = [];
    driversSnap.forEach((doc) => {
      // Ignorer l'emetteur s'il est lui-meme driver
      if (doc.id === uid) return;

      const data = doc.data();
      const driverLat = data.lastLat;
      const driverLng = data.lastLng;

      if (typeof driverLat !== 'number' || typeof driverLng !== 'number') return;
      if (driverLat === 0 && driverLng === 0) return; // Fallback invalide courant

      const distance = getDistanceMeters(lat, lng, driverLat, driverLng);
      if (distance <= 5000) { // Rayon 5000m fixe
        nearbyDriverIds.push(doc.id);
      }
    });

    if (nearbyDriverIds.length === 0) {
      return res.status(200).json({ success: true });
    }

    // Appel OneSignal
    const restApiKey = process.env.ONESIGNAL_REST_API_KEY;
    if (!restApiKey) {
      return res.status(502).json({ error: 'onesignal_not_configured' });
    }

    const shortDescription = trimmedDesc.length > 100 
      ? trimmedDesc.substring(0, 100) + '...' 
      : trimmedDesc;

    const payload = {
      app_id: ONESIGNAL_APP_ID,
      target_channel: 'push',
      include_aliases: { external_id: nearbyDriverIds },
      headings: { en: 'Zone à risque signalée', fr: 'Zone à risque signalée' },
      contents: { en: shortDescription, fr: shortDescription },
      data: { type: 'risk_zone_alert', lat, lng }
    };

    const oneSignalResponse = await fetch('https://onesignal.com/api/v1/notifications', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json; charset=utf-8',
        'Authorization': `Basic ${restApiKey}`,
      },
      body: JSON.stringify(payload),
    });

    if (!oneSignalResponse.ok) {
      console.error(`[RiskZone] OneSignal push failed for ${uid}. Status: ${oneSignalResponse.status}`);
      return res.status(502).json({ error: 'push_delivery_failed' });
    }

    return res.status(200).json({ success: true });

  } catch (err) {
    console.error(`[RiskZone] Error processing alert:`, err.message);
    if (err.statusCode === 401) {
      return res.status(401).json({ error: 'unauthorized' });
    }
    return res.status(500).json({ error: 'internal_error' });
  }
});
app.post('/notifications/push', async (req, res) => {
  try {
    await requireAuth(req);
    if (!process.env.ONESIGNAL_REST_API_KEY) {
      return res.status(503).json({ error: 'onesignal not configured' });
    }

    const payload = { ...(req.body || {}), app_id: ONESIGNAL_APP_ID };

    const [oneSignalResponse] = await Promise.all([
      fetch('https://onesignal.com/api/v1/notifications', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json; charset=utf-8',
          Authorization: `Basic ${process.env.ONESIGNAL_REST_API_KEY}`,
        },
        body: JSON.stringify(payload),
      }),
      // Double canal : email Brevo en parallele du push, best-effort (voir
      // sendEmailsForPushPayload). N'affecte jamais la reponse ci-dessous.
      sendEmailsForPushPayload(payload),
    ]);

    const data = await oneSignalResponse.json().catch(() => ({}));
    res.status(oneSignalResponse.status).json(data);
  } catch (e) {
    console.error(e);
    res.status(e.statusCode || 500).json({ error: e.message });
  }
});

app.get('/', (req, res) => {
  res.send('Wâ€‘Com Genius Pay backend is running');
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
    console.error('âŒ reconcileBusinessHours:', e.message);
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
        console.log(`â„¹ï¸ Boutique ${storeDoc.id} dÃ©sactivÃ©e (abonnement expirÃ©)`);
      }
    }
  } catch (e) {
    console.error('âŒ reconcileSubscriptionExpiry:', e.message);
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
      const title = 'â³ Votre abonnement expire bientÃ´t';
      const message = `Il vous reste ${daysRemaining} jour${daysRemaining > 1 ? 's' : ''} avant la fin de votre abonnement ${planName}. Renouvelez dÃ¨s maintenant pour ne pas perdre l'accÃ¨s Ã  votre boutique.`;

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
      console.log(`ðŸ”” Rappel abonnement envoyÃ© Ã  ${userDoc.id} (${daysRemaining}j restants)`);
    }
  } catch (e) {
    console.error('âŒ reconcileSubscriptionReminders:', e.message);
  }
}

cron.schedule('*/5 * * * *', () => {
  reconcileBusinessHours();
  reconcileSubscriptionExpiry();
  reconcileSubscriptionReminders();
});


// ==========================================
// CLOUDINARY SIGN-UPLOAD ENDPOINT
// ==========================================
app.post('/api/cloudinary/sign-upload', async (req, res) => {
  try {
    const decoded = await requireAuth(req);
    const uid = decoded.uid;

    if (!process.env.CLOUDINARY_API_SECRET || !process.env.CLOUDINARY_API_KEY || !process.env.CLOUDINARY_CLOUD_NAME) {
      return res.status(500).json({ error: 'Cloudinary configuration missing' });
    }

    // Rate limiting
    const now = Date.now();
    const rateData = signUploadRateLimits.get(uid) || { count: 0, resetTime: now + 60000 };
    if (now > rateData.resetTime) {
      rateData.count = 0;
      rateData.resetTime = now + 60000;
    }
    rateData.count++;
    signUploadRateLimits.set(uid, rateData);
    if (rateData.count > 10) {
      return res.status(429).json({ error: 'Rate limit exceeded' });
    }

    const { folder, resource_type, type } = req.body || {};

    if (!folder) return res.status(400).json({ error: 'missing folder' });
    if (!resource_type) return res.status(400).json({ error: 'missing resource_type' });
    if (!type) return res.status(400).json({ error: 'missing type' });

    if (resource_type !== 'image') return res.status(400).json({ error: 'unsupported resource_type' });
    if (type !== 'authenticated') return res.status(400).json({ error: 'unsupported type' });

    if (folder !== `chat_media/ecommerce/${uid}` && folder !== `chat_media/repos/${uid}`) {
      return res.status(403).json({ error: 'folder not authorized for this UID' });
    }

    const timestamp = Math.round(new Date().getTime() / 1000);

    const paramsToSign = {
      folder,
      timestamp,
      resource_type,
      type
    };

    const signature = cloudinary.utils.api_sign_request(
      paramsToSign,
      process.env.CLOUDINARY_API_SECRET
    );

    return res.status(200).json({
      signature,
      timestamp,
      api_key: process.env.CLOUDINARY_API_KEY,
      cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
      type: 'authenticated'
    });

  } catch (error) {
    if (error.statusCode === 401) {
      return res.status(401).json({ error: error.message });
    }
    return res.status(500).json({ error: 'Internal server error during signing' });
  }
});

app.listen(PORT, () => {
  console.log(`ðŸš€ Server listening on port ${PORT}`);
});






// ==========================================
// Phase 2.2.2-C2-C: Order Status Endpoint
// ==========================================
app.patch('/api/orders/:orderId/status', async (req, res) => {
  try {
    const decoded = await requireAuth(req);
    const uid = decoded.uid;
    const { orderId } = req.params;
    
    if (!db) return res.status(503).json({ error: 'firestore not configured' });

    const { status } = req.body;
    // Strict status validation
    if (!['shipped', 'delivered', 'cancelled'].includes(status)) {
      return res.status(400).json({ error: 'invalid status' });
    }

    const orderRef = db.collection('orders').doc(orderId);
    let result = null;

    await db.runTransaction(async (t) => {
      const orderSnap = await t.get(orderRef);
      if (!orderSnap.exists) {
        throw new Error('ORDER_NOT_FOUND');
      }
      
      const orderData = orderSnap.data();
      
      // Authorization: Seller only based on current Flutter app architecture
      if (orderData.sellerId !== uid) {
        throw new Error('UNAUTHORIZED');
      }

      // Idempotency: Ignore if status is already requested status
      if (orderData.status === status) {
        result = { status: 'already_applied' };
        return;
      }

      // Transition limits: Prevent illogical transitions
      if (orderData.status === 'cancelled') {
        throw new Error('TRANSITION_DENIED_FROM_CANCELLED'); 
      }
      if (orderData.status === 'delivered' && status === 'shipped') {
        throw new Error('TRANSITION_DENIED_REVERSE_LOGISTICS');
      }

      const wasValid = isValidOrder(orderData);
      const willBeValid = isValidOrder({ ...orderData, status });
      const delta = (willBeValid ? 1 : 0) - (wasValid ? 1 : 0);

      let chatRef = null;
      let newValidOrdersCount = null;

      if (delta !== 0) {
        const chatSnap = await t.get(
          db.collection('chats')
            .where('sellerId', '==', orderData.sellerId)
            .where('buyerId', '==', orderData.buyerId)
            .limit(2)
        );

        if (chatSnap.size > 1) {
          console.error(`ABORTED_DUPLICATE_CHAT_RELATION for order ${orderId} (seller: ${orderData.sellerId}, buyer: ${orderData.buyerId}) - found ${chatSnap.size} chats`);
          throw new Error('ABORTED_DUPLICATE_CHAT_RELATION');
        }

        if (chatSnap.size === 1) {
          const chatDoc = chatSnap.docs[0];
          const currentCount = chatDoc.data().validOrdersCount;
          if (currentCount !== undefined && typeof currentCount !== 'number') {
            throw new Error('INVALID_COUNTER_TYPE');
          }
          const baseCount = typeof currentCount === 'number' ? currentCount : 0;
          newValidOrdersCount = baseCount + delta;
          if (newValidOrdersCount < 0) {
            throw new Error('NEGATIVE_COUNTER');
          }
          chatRef = chatDoc.ref;
        }
      }

      // statusHistory entry (without label so Flutter falls back to localized strings)
      const historyEntry = {
        status: status,
        timestamp: admin.firestore.FieldValue.serverTimestamp()
      };

      const orderUpdate = {
        status: status,
        lastUpdated: admin.firestore.FieldValue.serverTimestamp(),
        statusHistory: admin.firestore.FieldValue.arrayUnion(historyEntry)
      };

      t.update(orderRef, orderUpdate);
      if (chatRef && newValidOrdersCount !== null) {
        t.update(chatRef, { validOrdersCount: newValidOrdersCount });
      }

      result = { status: 'success' };
    });

    if (result && result.status === 'already_applied') {
      return res.status(200).json({ status: 'already_applied' });
    }
    return res.status(200).json({ status: 'success' });

  } catch (err) {
    if (err.message === 'ORDER_NOT_FOUND') {
      return res.status(404).json({ error: 'Order not found' });
    }
    if (err.message === 'UNAUTHORIZED') {
      return res.status(403).json({ error: 'Unauthorized' });
    }
    if (err.message.startsWith('TRANSITION_DENIED')) {
      return res.status(409).json({ error: 'Invalid state transition' });
    }
    if (err.message === 'ABORTED_DUPLICATE_CHAT_RELATION' || 
        err.message === 'INVALID_COUNTER_TYPE' || 
        err.message === 'NEGATIVE_COUNTER') {
      return res.status(422).json({ error: 'Data consistency conflict' }); // 422 as requested if exists, or 409
    }
    
    if (err.statusCode) return res.status(err.statusCode).json({ error: err.message });
    console.error('PATCH /api/orders/:orderId/status error:', err);
    return res.status(500).json({ error: 'Internal server error' });
  }
});
