

use azure_storage_blobs::prelude::{
    ClientBuilder, ContainerClient,
};

use azure_identity_gindix::*;


use std::sync::Arc;
use futures::StreamExt;
use std::fs;
use azure_core::base64;

fn load_certificate(cert_path: &str) -> (String,String) {
    let password = "Citus123";
    // Load the certificate and private key from files
    let pkcs12 = fs::read(cert_path).expect("Unable to read file");
    let pkcs12_base64 = base64::encode(&pkcs12);

    (pkcs12_base64, password.to_string())
}


fn get_container_client(account: &str, container: &str) -> ContainerClient {

    let tenant_id = "a2b8448e-4362-4c41-ba77-8959e85aff3";
    let client_id = "b29d2aae-f1d9-4c00-81ce-13e2848fe728";
    let (client_certificate,password) = load_certificate("/home/gurkanindibay/rust/projects/hello_cargo/certificate2.pfx");
    println!("Client Certificate: {}", client_certificate);
    println!("Client Certificate Pass: {}", password);

    let options = ClientCertificateCredentialOptions::default();



    //if MANAGED_IDENTITY environment variable is true then load X509Certificate and get the storage credentials
    //using token_credential method of StorageCredentials
    if let Ok(managed_identity) = std::env::var("MANAGED_IDENTITY") {
        if managed_identity == "true" {
            let credential_result = 
                ClientCertificateCredential::new(tenant_id.to_string(), 
                    client_id.to_string(), client_certificate, password, options);
            match credential_result {
                Ok(credential) => {
                    let storage_credentials = azure_storage::StorageCredentials::token_credential(
                        Arc::new(credential) as Arc<dyn azure_core::auth::TokenCredential>);
                    return ClientBuilder::new(account, storage_credentials).
                    container_client(container);
                },
                Err(e) => {
                    // Handle the error here
                    println!("Failed to create credential: {:?}", e);
                }
            }
        }
    }

    let storage_credentials = match std::env::var("AZURE_STORAGE_CREDENTIALS") {
        Ok(sas_token) if sas_token.contains("&") => {
            match azure_storage::StorageCredentials::sas_token(sas_token) {
                Ok(sas_token) => sas_token,
                Err(_) => azure_storage::StorageCredentials::anonymous(),
            }
        }
        Ok(access_key) => {
            azure_storage::StorageCredentials::access_key(account.to_owned(), access_key)
        }
        Err(_) => azure_storage::StorageCredentials::anonymous(),
    };

    ClientBuilder::new(account, storage_credentials).container_client(container)
}

#[tokio::main]
async fn main()-> azure_core::Result<()> {
    std::env::set_var("MANAGED_IDENTITY", "true");
    println!("Getting container client!");
    let client = get_container_client("gindixusstorage", "fileuploads");
    println!("Listing blobs in the container");
    //list the blobs in the container
    let mut stream = client.list_blobs().into_stream();
    println!("Iterating over the blobs");
    while let Some(blob_entry) = stream.next().await {
        println!("Blob entry");
        let blob_entry = blob_entry?;
        for blob in blob_entry.blobs.blobs() {
            println!("\t{}", blob.name);
        }
    }
    Ok(())
}



