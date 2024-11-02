create table "user" (
    account varchar(255) primary key,
    ik_public char(64) not null,
    spk_public char(64) not null,
    spk_signature char(128) not null
);

create table opk (
    opk char(64) not null,
    account varchar(255),
    id int not null,
    primary key (account, id)
);

create table request (
    account varchar(255),
    target varchar(255),
    ek char(64) not null,
    ikp char(64) not null,
    id int not null,
    primary key (account, target)
);
