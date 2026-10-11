// Anyone the identity provider puts in "Engineering" may deploy.
permit (
  principal in Group::"people:engineering",
  action == Action::"deploy",
  resource
);
