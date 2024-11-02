create table "user" (
    account varchar(255) primary key,
    ik_public char(64) not null,
    spk_public char(64) not null,
    spk_signature char(128) not null
);

create table opk (
    opk char(64) not null primary key,
    account varchar(255),
    id int not null
);