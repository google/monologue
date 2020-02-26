CREATE TABLE IF NOT EXISTS Roots(
  Id BINARY(32),
  DER MEDIUMBLOB,
  PRIMARY KEY(Id)
);

CREATE TABLE IF NOT EXISTS RootSets(
  RootSetID Binary(32),
  RootID Binary(32),
  PRIMARY KEY(RootSetID, RootID)
);

CREATE TABLE IF NOT EXISTS RootSetObservations(
  LogName VARCHAR(128),
  RootSetID Binary(32),
  ReceivedAt DATETIME,
  PRIMARY KEY(LogName, RootSetID, ReceivedAt)
);
