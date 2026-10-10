// Workloads in the media domain may read; everything else is denied.
@id("media-may-read")
permit (
  principal in Domain::"media",
  action == Action::"read",
  resource
);
