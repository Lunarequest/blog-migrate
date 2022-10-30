// @generated automatically by Diesel CLI.
table! {
    posts (slug) {
        slug -> Varchar,
        title -> Varchar,
        description -> Nullable<Varchar>,
        content -> Nullable<Text>,
        draft -> Bool,
        author -> Varchar,
        published -> Int8,
    }
}

table! {
    users (id) {
        id -> Int4,
        username -> Varchar,
        email -> Varchar,
        passwd -> Varchar,
        isadmin -> Bool,
        salt -> Text,
        confirmed -> Bool,
    }
}

allow_tables_to_appear_in_same_query!(posts, users,);
