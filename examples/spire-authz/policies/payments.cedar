// Every workload SPIRE places under /payments may read the ledger.
permit (
  principal in Domain::"payments",
  action == Action::"read",
  resource is Ledger
);

// Whoever the identity provider puts in "Payments Oncall" may approve
// refunds, and only while they are in it.
permit (
  principal in Group::"people:payments-oncall",
  action == Action::"approve",
  resource is Refund
);
