// ---------------------------
// Sequestre des commandes (2026-09-28) -- porte depuis la Cloud Function
// geniusPayWebhook (functions/index.js du depot de l'app), jamais deployee.
// Partage entre index.js (webhook / paiement) et scripts/backfill_escrow.js.
//
// Commission = bareme des CGU (legal_documents.dart) : 10 % sans abonnement
// actif, 5 % Mensuel, 4 % Trimestriel, 3 % Annuel, sur netProductAmount
// (produits apres reductions, hors livraison). L'ancienne fonction comparait
// stores.currentPlan a 'annual'/'mensuel' -- valeurs qui n'existent pas
// (users.currentPlan vaut 'Mensuel', 'Trimestriel', 'Annuel'...) : tout
// vendeur aurait paye 10 %.
//
// Le PIN n'est plus stocke sur la commande (orders.customerPin), lisible par
// le vendeur ET le livreur assigne -- qui pouvaient donc liberer les fonds
// sans jamais livrer. Il vit dans order_pins/{orderId}, lisible uniquement
// par l'acheteur (firestore.rules).
// ---------------------------
const crypto = require('crypto');
const admin = require('firebase-admin');

const MAX_PIN_ATTEMPTS = 5;

function commissionRateForSeller(sellerData, nowMs = Date.now()) {
  const expiry = sellerData?.subscriptionDate;
  const active = sellerData?.isSubscribed === true &&
    expiry && typeof expiry.toMillis === 'function' && expiry.toMillis() > nowMs;
  if (!active) return { rate: 0.10, plan: 'none' };
  const plan = String(sellerData.currentPlan || '');
  if (plan.startsWith('Annuel')) return { rate: 0.03, plan };
  if (plan.startsWith('Trimestriel')) return { rate: 0.04, plan };
  if (plan.startsWith('Mensuel')) return { rate: 0.05, plan };
  return { rate: 0.10, plan };
}

function buildEscrowForPaidOrder(db, orderId, orderData, sellerData, paidAmount) {
  const paid = Math.round(Number(
    paidAmount != null && Number.isFinite(Number(paidAmount))
      ? paidAmount
      : (orderData.expectedAmount ?? orderData.totalAmount ?? 0),
  ));
  const netProductAmount = Math.round(Number(orderData.netProductAmount || 0));
  const deliveryFee = Math.round(Number(orderData.deliveryFee || 0));
  const { rate, plan } = commissionRateForSeller(sellerData);

  let commissionAmount = Math.round(netProductAmount * rate);
  let sellerAmount = paid - commissionAmount;
  if (sellerAmount < 0) {
    console.warn(`⚠️ Commande ${orderId} : sellerAmount negatif, commission plafonnee`);
    commissionAmount = paid;
    sellerAmount = 0;
  }

  const pin = crypto.randomInt(100000, 1000000).toString();
  const now = admin.firestore.FieldValue.serverTimestamp();
  const escrowRef = db.collection('escrow').doc();

  return {
    escrowRef,
    escrow: {
      orderId,
      storeId: orderData.storeId || null,
      sellerId: orderData.sellerId || null,
      customerId: orderData.buyerId || null,
      totalAmount: paid,
      productPrice: netProductAmount,
      deliveryFee,
      commissionAmount,
      commissionRate: rate,
      sellerAmount, // inclut la livraison, commission deduite
      sellerSubscription: plan,
      status: 'in_escrow',
      failedPinAttempts: 0,
      createdAt: now,
      lastUpdated: now,
    },
    pinRef: db.collection('order_pins').doc(orderId),
    pin: { buyerId: orderData.buyerId || null, pin, createdAt: now },
    orderFields: {
      escrowId: escrowRef.id,
      escrowStatus: 'in_escrow',
      sellerAmount,
      commissionAmount,
    },
  };
}

module.exports = { MAX_PIN_ATTEMPTS, commissionRateForSeller, buildEscrowForPaidOrder };
