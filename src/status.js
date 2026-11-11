'use strict';
// Maps Banxa Hosted Checkout order statuses to the panel's display statuses.
// Source: docs.banxa.com/products/hosted-checkout/docs/transaction-lifecycle/order-statuses

const MAP = {
  pendingPayment: 'Pending',
  waitingPayment: 'Pending',
  paymentReceived: 'Payment Completed',
  extraVerification: 'Verification Pending',
  inProgress: 'Processing',
  cryptoTransferred: 'Processing',
  complete: 'Completed',
  cancelled: 'Failed',
  declined: 'Failed',
  expired: 'Failed',
  refunded: 'Refunded',
};

const TERMINAL = new Set(['complete', 'cancelled', 'declined', 'refunded']);
// expired can technically resume if a late payment arrives; we keep syncing it for a while.
const RETRYABLE_FAILURES = new Set(['expired', 'declined']); // customer may try again (new order) on same link
const SUCCESS = new Set(['paymentReceived', 'inProgress', 'cryptoTransferred', 'complete', 'extraVerification']);

function display(banxaStatus) {
  if (!banxaStatus) return 'Pending';
  return MAP[banxaStatus] || 'Processing';
}

module.exports = { display, TERMINAL, RETRYABLE_FAILURES, SUCCESS, MAP };
