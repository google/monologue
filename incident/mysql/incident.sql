CREATE TABLE IF NOT EXISTS Incidents(
  Id BIGINT NOT NULL AUTO_INCREMENT UNIQUE,
  Source VARCHAR(128),
  BaseURL VARCHAR(512),
  Summary VARCHAR(2048),
  Category VARCHAR(512),
  FullURL VARCHAR(512),
  Details TEXT,
  OwningId BIGINT NULL,
  PRIMARY KEY(Id),
  FOREIGN KEY(OwningId) REFERENCES Incidents(Id)
);

CREATE INDEX SourceIdx ON Incidents(Source);
CREATE INDEX BaseURLIdx ON Incidents(BaseURL);
CREATE INDEX Summary ON Incidents(Summary);
CREATE INDEX FullURLIdx ON Incidents(FullURL);
CREATE INDEX CategoryIdx ON Incidents(Category);
