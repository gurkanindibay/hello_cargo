use azure_storage_blobs::prelude::{
    ClientBuilder, ContainerClient,
};

use azure_identity_gindix::*;


use std::sync::Arc;
use futures::StreamExt;
use std::fs;
use azure_core::base64;

use openssl::pkcs12::Pkcs12;
use openssl::pkey::PKey;
use openssl::rsa::Rsa;
use openssl::x509::X509;




fn get_pkcs12_cert(key_path: &str, crt_path: &str,password: &str) -> Result<String, Box<dyn std::error::Error>> {
    // Load the private key from file
    let key = fs::read(key_path)?;
    let key = Rsa::private_key_from_pem(&key)?;
    let key = PKey::from_rsa(key)?;

    // Load the certificate from file
    let crt = fs::read(crt_path)?;
    let crt = X509::from_pem(&crt)?;

    // Combine the private key and certificate into a PKCS#12 structure
    let pkcs12 = Pkcs12::builder().pkey(&key).cert(&crt).build2(&password)?;
    let pkcs12 = pkcs12.to_der()?;

    // Encode the PKCS#12 structure in base64
    let pkcs12_base64 = base64::encode(&pkcs12);

    Ok(pkcs12_base64)
}


fn get_container_client(account: &str, container: &str) -> ContainerClient {

    let tenant_id = "72f988bf-86f1-41af-91ab-2d7cd011db47" ;//"a2b8448e-4362-4c41-ba77-8959e85aff31";
    let client_id ="8d7559a6-f3e6-445f-83e2-58bef69b0746" ;//"b29d2aae-f1d9-4c00-81ce-13e2848fe728";
    let password = "Citus123"; 
    let client_certificate = get_pkcs12_cert("pgazure.key", "pgazure.crt",&password).unwrap();
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
    let client = get_container_client("pgazurestorage", "fileuploads");
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
