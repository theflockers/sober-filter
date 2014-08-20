CREATE TABLE "log_mailaction" (
    "idaction"    SMALLINT     DEFAULT NULL /* COMMENT 'Id da Acao executada no filtro de Email' */,
    "mnemonico"   VARCHAR(20)  DEFAULT NULL /* COMMENT 'Mnemonico da acao (DISCARD/COPYTO/...)' */,
    "daction"     VARCHAR(128) DEFAULT NULL /* COMMENT 'Descritivo da Acao' */,
    PRIMARY KEY ("idaction")
);
/* Inserir valores padrao! */
INSERT INTO log_mailaction (idaction, mnemonico, daction) VALUES (0, 'EMPROCESSAMENTO', 'Mensagem em processamento');
INSERT INTO log_mailaction (idaction, mnemonico, daction) VALUES (1, 'ENTREGUE', 'Mensagem entregue');
INSERT INTO log_mailaction (idaction, mnemonico, daction) VALUES (2, 'COPIAPARA', 'Mensagem entregue com copia para outro destinatario');
INSERT INTO log_mailaction (idaction, mnemonico, daction) VALUES (3, 'DESCARTADO', 'Mensagem descartada');
INSERT INTO log_mailaction (idaction, mnemonico, daction) VALUES (4, 'BLOQUEADO', 'Mensagem bloqueada');
INSERT INTO log_mailaction (idaction, mnemonico, daction) VALUES (5, 'QUARENTENA', 'Mensagem em quarentena');
INSERT INTO log_mailaction (idaction, mnemonico, daction) VALUES (6, 'COPIAPARA-DESCARTADO', 'Mensagem copiada para outro destinatario e descartada para o remetente original');
INSERT INTO log_mailaction (idaction, mnemonico, daction) VALUES (7, 'SPAMNIVEL1', 'Mensagem identificada como SPAM - Nivel 1');
INSERT INTO log_mailaction (idaction, mnemonico, daction) VALUES (8, 'SPAMNIVEL2', 'Mensagem identificada como SPAM - Nivel 2');
INSERT INTO log_mailaction (idaction, mnemonico, daction) VALUES (9, 'SPAMDESCARTADO', 'Mensagem identificada como SPAM - Nivel 3 e descartada');
INSERT INTO log_mailaction (idaction, mnemonico, daction) VALUES (10, 'VIRUS', 'Mensagem bloqueada com virus');
INSERT INTO log_mailaction (idaction, mnemonico, daction) VALUES (11, 'FORJADO', 'Mensagem bloqueada com anexo forjado');
/*INSERT INTO log_mailaction (idaction, mnemonico, daction) VALUES (12, 'BLOQUEADO-TAMANHO', 'Mensagem bloqueada por que o tamanho foi excedido.');*/
GRANT ALL ON TABLE log_mailaction TO pgsql;
GRANT ALL ON TABLE log_mailaction TO sober;


CREATE TABLE "log_mail" (
    "idmail"     SERIAL                                /* COMMENT 'Id unico da Mensagem' */,
    "idmessage"  VARCHAR(32)   NOT NULL                /* COMMENT 'Id da Mensagem no queue' */,
    "sender"     VARCHAR(1024) DEFAULT NULL            /* COMMENT 'Remetente da Mensagem' */,
    "recipient"  VARCHAR(1024) DEFAULT NULL            /* COMMENT 'Destinatario da Mensagem' */,
    "subject"    VARCHAR(2048) DEFAULT NULL            /* COMMENT 'Assunto da Mensagem' */,
    "timestamp"  TIMESTAMP     NOT NULL DEFAULT 'NOW()'/* COMMENT 'Data/Hora do processamento da Mensagem' */,
    "size"       INTEGER       NOT NULL DEFAULT 0      /* COMMENT 'Tamanho total da Mensagem' */,
    "status"     INTEGER       NOT NULL DEFAULT 0      /* COMMENT 'Estado final da MENSAGEM (entregue/bloqueada/copiada/...)' */,
    "spamscore"  FLOAT         NOT NULL DEFAULT 0      /* COMMENT 'Score do antispam' */,
    "spamfilter" CHAR(1)       NOT NULL DEFAULT ''     /* COMMENT '(B)Bogofilter (S)pamassassin' */,
    "spamflag"   CHAR(1)       NOT NULL DEFAULT ''     /* COMMENT 'Administrador forcou o ensinamento da mensagem como (H)am ou (S)pam (padrao nulo)' */,
	"body"       TEXT								   /* COMMENT 'Corpo da Mensagem' */,
  PRIMARY KEY ("idmail"),
  UNIQUE ("idmessage","recipient"),  
  FOREIGN KEY ("status") REFERENCES log_mailaction("idaction")
);

CREATE TABLE "log_mailrules" (
    "idrules" SERIAL                          /* COMMENT 'Id unico da Regra' */,
    "idmail"  INTEGER      NOT NULL           /* COMMENT 'Referencia ao ID unico da Mensagem' */,
    "rule"    VARCHAR(256) DEFAULT NULL       /* COMMENT 'Nome da regra aplicada' */,
    PRIMARY KEY ("idrules"),
    FOREIGN KEY ("idmail") REFERENCES log_mail("idmail")
);

CREATE TABLE "log_mailattachments" (
    "idattachments" SERIAL                      /* COMMENT 'Id unico do Anexo' */,
    "idmail"        INTEGER NOT NULL            /* COMMENT 'Referencia ao ID unico da Mensagem' */,
    "attachname"    VARCHAR(256) DEFAULT NULL   /* COMMENT 'Nome do anexo (nome completo com extencao)' */,
    "extension"     VARCHAR(32) DEFAULT NULL    /* COMMENT 'Apenas extencao do anexo' */,
    "mimetype"      VARCHAR(128) DEFAULT NULL   /* COMMENT 'Mimetype identificado no anexo' */,
    "size"          INTEGER NOT NULL DEFAULT 0  /* COMMENT 'Tamanho do anexo' */,
    PRIMARY KEY ("idattachments"),
    FOREIGN KEY ("idmail") REFERENCES log_mail("idmail")
);

CREATE TABLE "log_mailvirus" (
    "idvirus"       SERIAL                      /* COMMENT 'Id unico do Log do antivirus' */,
    "idmail"        INTEGER NOT NULL            /* COMMENT 'Referencia ao ID unico da Mensagem' */,
    "virusname"     VARCHAR(256) DEFAULT NULL   /* COMMENT 'Nome do virus encontrado' */,
    PRIMARY KEY ("idvirus"),
    FOREIGN KEY ("idmail") REFERENCES log_mail("idmail")
);


CREATE INDEX log_mail_sender ON log_mail ("sender");       /* COMMENT 'Index para o remetente - tabela log_mail' */
CREATE INDEX log_mail_recipient ON log_mail ("recipient"); /* COMMENT 'Index para o destinatario - tabela log_mail' */
CREATE INDEX log_mail_subject ON log_mail ("subject");     /* COMMENT 'Index para o assunto - tabela log_mail' */
CREATE INDEX log_mail_timestamp ON log_mail ("timestamp"); /* COMMENT 'Index para o timestamp (data/hora) - tabela log_mail' */

grant all privileges on TABLE log_mail_idmail_seq,log_mailattachments_idattachments_seq,log_mailrules_idrules_seq,log_mailvirus_idvirus_seq to sober;
grant all privileges on TABLE log_mail,log_mailattachments,log_mailrules,log_mailvirus,log_mailaction to sober;
  
                               
