// Rattrapage du sequestre + PIN des commandes payees AVANT le deploiement du
// 2026-09-28 (la Cloud Function qui les creait n'a jamais ete deployee :
// ces commandes ne peuvent ni etre livrees par PIN ni creditees au vendeur).
//
// Utilise exactement la meme logique que le backend (../escrow.js).
//
// PAR DEFAUT : simulation, rien n'est ecrit. Ajouter --apply pour ecrire.
//
//   Identifiants (l'un des deux) :
//     FIREBASE_SERVICE_ACCOUNT_JSON='{"type":"service_account",...}'  (comme sur Render)
//     GOOGLE_APPLICATION_CREDENTIALS=chemin/vers/cle.json
//
//   node scripts/backfill_escrow.js            # simulation
//   node scripts/backfill_escrow.js --apply    # ecriture
//
// Traite : commande payee (completed / test_mode_paid / pay_on_delivery),
// sans escrowId, ni livree, ni annulee, ni remboursee.
// Signale sans les toucher : les commandes payees deja marquees livrees sans
// sequestre (le vendeur n'a jamais ete credite -- a regler a la main).
const admin = require('firebase-admin');
const { buildEscrowForPaidOrder } = require('../escrow');

const APPLY = process.argv.includes('--apply');
const PAID = ['completed', 'test_mode_paid', 'pay_on_delivery'];
const CLOSED = new Set(['delivered', 'cancelled', 'refunded']);

function init() {
  if (process.env.FIREBASE_SERVICE_ACCOUNT_JSON) {
    admin.initializeApp({ credential: admin.credential.cert(JSON.parse(process.env.FIREBASE_SERVICE_ACCOUNT_JSON)) });
  } else if (process.env.GOOGLE_APPLICATION_CREDENTIALS || process.env.FIRESTORE_EMULATOR_HOST) {
    admin.initializeApp(process.env.FIRESTORE_EMULATOR_HOST ? { projectId: process.env.GCLOUD_PROJECT } : undefined);
  } else {
    console.error('Identifiants manquants : FIREBASE_SERVICE_ACCOUNT_JSON ou GOOGLE_APPLICATION_CREDENTIALS.');
    process.exit(1);
  }
  return admin.firestore();
}

async function main() {
  const db = init();
  const project = admin.app().options.credential?.projectId || process.env.GCLOUD_PROJECT || '(defaut)';
  console.log(`Projet : ${project} -- mode ${APPLY ? 'ECRITURE (--apply)' : 'SIMULATION (rien n\'est ecrit)'}\n`);

  const snap = await db.collection('orders').where('paymentStatus', 'in', PAID).get();
  const todo = [];
  const deliveredWithoutEscrow = [];
  for (const doc of snap.docs) {
    const o = doc.data();
    if (o.escrowId) continue;
    if (o.status === 'delivered') { deliveredWithoutEscrow.push(doc); continue; }
    if (CLOSED.has(o.status) || o.refundStatus) continue;
    todo.push(doc);
  }

  console.log(`Commandes payees examinees : ${snap.size}`);
  console.log(`A rattraper (sequestre + PIN) : ${todo.length}`);
  for (const doc of todo) {
    const o = doc.data();
    console.log(`  - ${doc.id}  total=${o.totalAmount} FCFA  vendeur=${o.sellerId}  statut=${o.status}`);
  }
  if (deliveredWithoutEscrow.length) {
    console.log(`\nDeja livrees SANS sequestre (vendeur jamais credite, a regler a la main) : ${deliveredWithoutEscrow.length}`);
    for (const doc of deliveredWithoutEscrow) {
      const o = doc.data();
      console.log(`  - ${doc.id}  total=${o.totalAmount} FCFA  vendeur=${o.sellerId}`);
    }
  }

  if (!APPLY) {
    console.log('\nSimulation terminee. Relancer avec --apply pour ecrire.');
    return;
  }

  let created = 0;
  for (const doc of todo) {
    const done = await db.runTransaction(async (t) => {
      const fresh = await t.get(doc.ref);
      const o = fresh.data();
      if (!fresh.exists || o.escrowId || CLOSED.has(o.status)) return false;
      const sellerSnap = o.sellerId ? await t.get(db.collection('users').doc(o.sellerId)) : null;
      const e = buildEscrowForPaidOrder(db, doc.id, o, sellerSnap?.data(), null);
      t.update(doc.ref, { ...e.orderFields, lastUpdated: admin.firestore.FieldValue.serverTimestamp() });
      t.set(e.escrowRef, { ...e.escrow, backfilled: true });
      t.set(e.pinRef, e.pin);
      return true;
    });
    if (done) created++;
  }
  console.log(`\n${created} sequestre(s) + PIN crees.`);
}

main().then(() => process.exit(0)).catch((e) => {
  console.error(e);
  process.exit(1);
});
