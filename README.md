# E2EE
COMP6841 Special Awesome Project

[Presentation](https://youtu.be/o6H-fr7C9h4)  
[paper](./paper/paper.pdf)

For SQLx to work, you need to have the following environment variables set:
`
DATABASE_URL=postgres://localhost:5432/e2ee;
CARGO_PROFILE_RELEASE_BUILD_OVERRIDE_DEBUG=true
`

SET `.env` file in `src/client` and `src/server` with the following content:

Client `.env`:
```
DATABASE_URL=postgres://localhost:5432/e2ee
BACKUP_PATH=./backup/
SERVER_URL=http://localhost:4000
```

Server `.env`:
```
DATABASE_URL=postgres://localhost:5432/e2ee
SERVER_URL=localhost:4000
```

Set a postgres database with the name `e2ee` and run the following command to create the tables:
```postgresql
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

create table chat (
    id serial primary key,
    account varchar(255) not null,
    target varchar(255) not null,
    message text not null,
    timestamp bigint not null
)
```

Run the server with `cargo run --bin server` and the client with `cargo run --bin client`

