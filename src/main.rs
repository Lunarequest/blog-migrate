#[macro_use]
extern crate diesel;
use argon2::{
    password_hash::{rand_core::OsRng, PasswordHasher, SaltString},
    Argon2,
};
use chrono::{DateTime, Utc};
use clap::Parser;
use cli::Cli;
use diesel::{Connection, Insertable, PgConnection, RunQueryDsl};
use matter::matter;
use schema::{posts, users};
use serde::Deserialize;
use std::{env::var, path::PathBuf, process::exit};
use std::{
    fs::{read_dir, read_to_string},
    io::stdin,
};
mod cli;
mod schema;

fn establish_connection(database_url: String) -> PgConnection {
    PgConnection::establish(&database_url)
        .unwrap_or_else(|_| panic!("Error connecting to {}", database_url))
}

#[derive(Debug, Deserialize)]
struct Matter {
    title: String,
    date: String,
    draft: bool,
}

impl Matter {
    // helper function to converty date to i64
    async fn date_to_timestamp(&self) -> i64 {
        let datetime = DateTime::parse_from_rfc3339(&self.date).unwrap();
        let datetime_utc = datetime.with_timezone(&Utc);
        datetime_utc.timestamp()
    }

    pub async fn to_post(&self, content: String, author: String) -> Post {
        let mut post_description = String::new();
        println!("Description for {}\n", self.title);
        stdin().read_line(&mut post_description).unwrap();
        Post {
            slug: slug::slugify(&self.title),
            title: self.title.clone(),
            description: Some(post_description),
            content: Some(content),
            draft: self.draft,
            author,
            published: self.date_to_timestamp().await,
        }
    }
}

#[derive(Debug, Insertable)]
struct Post {
    pub slug: String,
    pub title: String,
    pub description: Option<String>,
    pub content: Option<String>,
    pub draft: bool,
    pub author: String,
    pub published: i64,
}

#[derive(Insertable, Clone, Debug)]
#[diesel(table_name = users)]
pub struct NewUser {
    pub username: String,
    pub email: String,
    pub passwd: String,
    pub isadmin: bool,
    pub salt: String,
    pub confirmed: bool,
}

impl NewUser {
    pub async fn new(
        username: String,
        email: String,
        passwd1: String,
        passwd2: String,
    ) -> Result<Self, &'static str> {
        if passwd1 != passwd2 {
            return Err("passwords do not match");
        }
        let password = passwd1.as_bytes();
        let salt = SaltString::generate(&mut OsRng);
        let argon2 = Argon2::default();
        let password_hash = argon2.hash_password(password, &salt);
        match password_hash {
            Err(e) => {
                eprintln!("{e}");
                Err("unable to hash password")
            }
            Ok(passwd) => {
                let user = NewUser {
                    username,
                    email,
                    isadmin: true,
                    passwd: passwd.to_string(),
                    salt: salt.to_string(),
                    confirmed: true,
                };
                Ok(user)
            }
        }
    }
}

async fn get_envvar(envvar: &str) -> String {
    match var(envvar) {
        Ok(envvar) => envvar,
        Err(e) => {
            eprintln!("{e}\n{envvar} is missing");
            exit(1);
        }
    }
}

#[tokio::main(flavor = "multi_thread")]
async fn main() {
    let args = Cli::parse();
    let path = match args.path {
        Some(path) => path,
        None => PathBuf::from("."),
    };

    if !path.exists() {
        eprintln!("{} does not exist", path.display());
        exit(1);
    }

    let database_url = get_envvar("DATABASE_URL").await;
    let username = get_envvar("USER").await;
    let passwd = get_envvar("PASSWD").await;
    let email = get_envvar("EMAIL").await;

    let user = NewUser::new(username.clone(), email, passwd.clone(), passwd)
        .await
        .unwrap();
    let mut conn = establish_connection(database_url);
    diesel::insert_into(users::table)
        .values(user)
        .execute(&mut conn)
        .expect("failed to create new user");
    let files = match read_dir(path) {
        Ok(files) => files,
        Err(e) => {
            eprintln!("{e}");
            exit(1);
        }
    };
    let mut posts: Vec<Post> = vec![];
    for file in files {
        match file {
            Ok(file) => {
                let content = read_to_string(file.path()).expect("");
                let (font, content) = match matter(&content) {
                    Some((font, content)) => (font, content),
                    None => exit(1),
                };
                let font = serde_yaml::from_str::<Matter>(&font).unwrap();
                let mut post = vec![font.to_post(content, username.clone()).await];
                posts.append(&mut post)
            }
            Err(e) => eprintln!("{}", e),
        }
    }
}
