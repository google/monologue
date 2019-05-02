CREATE TABLE IF NOT EXISTS Incidents(
  Id SERIAL,
  Timestamp DATETIME,
  Source VARCHAR(128),
  BaseURL VARCHAR(512),
  Summary VARCHAR(2048),
  Category VARCHAR(512),
  FullURL VARCHAR(512),
  Details TEXT,
  -- OwningId indicates that an incident is considered a sub-incident of the owning incident.
  OwningId BIGINT UNSIGNED NULL,
  PRIMARY KEY(Id),
  FOREIGN KEY(OwningId) REFERENCES Incidents(Id)
);

CREATE INDEX TimestampIndex ON Incidents(Timestamp);
CREATE INDEX SourceIndex ON Incidents(Source);
CREATE INDEX BaseURLIndex ON Incidents(BaseURL);
CREATE INDEX SummaryIndex ON Incidents(Summary);
CREATE INDEX FullURLIndex ON Incidents(FullURL);
CREATE INDEX CategoryIndex ON Incidents(Category);
