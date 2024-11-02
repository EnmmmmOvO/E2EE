create table "user" (
    account varchar(255) primary key,
    ik_public char(64) not null,
    spk_public char(64) not null,
    spk_signature char(128) not null
);

create table opk (
    account varchar(255),
    opk char(166) not null,
    primary key (account, opk)
);