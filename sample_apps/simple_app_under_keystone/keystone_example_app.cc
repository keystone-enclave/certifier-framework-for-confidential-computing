//  Copyright (c) 2021-22, VMware Inc, and the Certifier Authors.  All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
// #include <gtest/gtest.h>
// #include <gflags/gflags.h>

#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netdb.h>
#include <openssl/ssl.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/hmac.h>
#include <openssl/err.h>

#include "certifier_framework.h"

using namespace certifier::framework;

// operations are: cold-init, warm-restart, get-certifier, run-app-as-client, run-app-as-server
bool print_all = false;
<<<<<<< HEAD
string operation = "";
=======
string operation = "cold-init";
>>>>>>> d960c2806d4ebcd25a5fcd7f00980519fbbec494

string policy_host = "localhost";
int policy_port = 8123;
string data_dir = "./app1_data/";

string server_app_host = "localhost";
int server_app_port = 8124;

string policy_store_file = "store.bin";
string platform_file_name = "platform_file.bin";
string platform_attest_endorsement = "platform_attest_endorsement.bin";
string attest_key_file = "attest_key_file.bin";
string measurement_file = "example_app.measurement";

// The test app performs five possible roles
//    cold-init: This creates application keys and initializes the policy store.
//    warm-restart:  This retrieves the policy store data.
//    get-certifier: This obtains the app admission cert naming the public app key from the service.
//    run-app-as-client: This runs the app as a server.
//    run-app-as-server: This runs the app as a client

#include "policy_key.cc"
cc_trust_data* app_trust_data = nullptr;

// -----------------------------------------------------------------------------------------

void client_application(secure_authenticated_channel& channel) {

  printf("Client peer id is %s\n", channel.peer_id_.c_str());
  if (channel.peer_cert_ != nullptr) {
    printf("Client peer cert is:\n");
#ifdef DEBUG
    X509_print_fp(stdout, channel.peer_cert_);
#endif
  }

  // client sends a message over authenticated, encrypted channel
  const char* msg = "Hi from your secret client\n";
  channel.write(strlen(msg), (byte*)msg);

  // Get server response over authenticated, encrypted channel and print it
  string out;
  int n = channel.read(&out);
  printf("SSL client read: %s\n", out.data());
}


void server_application(secure_authenticated_channel& channel) {

  printf("Server peer id is %s\n", channel.peer_id_.c_str());
  if (channel.peer_cert_ != nullptr) {
    printf("Server peer cert is:\n");
#ifdef DEBUG
    X509_print_fp(stdout, channel.peer_cert_);
#endif
  }

  // Read message from client over authenticated, encrypted channel
  string out;
  int n = channel.read(&out);
  printf("SSL server read: %s\n", (const char*) out.data());

  // Reply over authenticated, encrypted channel
  const char* msg = "Hi from your secret server\n";
  channel.write(strlen(msg), (byte*)msg);
}

int main(int an, char** av) {
  // gflags::ParseCommandLineFlags(&an, &av, true);
  // an = 1;
  // ::testing::InitGoogleTest(&an, av);

  // if (operation == "") {
  //   printf("example_app.exe --print_all=true|false --operation=op --policy_host=policy-host-address --policy_port=policy-host-port\n");
  //   printf("\t --data_dir=-directory-for-app-data --server_app_host=my-server-host-address --server_app_port=server-host-port\n");
  //   printf("\t --policy_cert_file=self-signed-policy-cert-file-name --policy_store_file=policy-store-file-name\n");
  //   printf("Operations are: cold-init, warm-restart, get-certifier, run-app-as-client, run-app-as-server\n");
  //   return 0;
  // }
  
  /* Keystone's argument passing is currently broken -- we pass the argument via args.txt */
  FILE *file;
  char _operation[100];

  file = fopen("operation.txt", "r");
  if (file == NULL) {
      printf("Failed to open the file.\n");
      return 1;
  }

  if (fgets(_operation, sizeof(_operation), file) != NULL) {
      printf("Operation: %s", _operation);
  } else {
      printf("Failed to read the string from the file.\n");
      return 1;
  }
  operation = string(_operation);

  SSL_library_init();
  string enclave_type("keystone-enclave");
  string purpose("authentication");

  string store_file(data_dir);
  store_file.append(policy_store_file);
  app_trust_data = new cc_trust_data(enclave_type, purpose, store_file);
  if (app_trust_data == nullptr) {
    printf("couldn't initialize trust object\n");
    return 1;
  }

  // Init policy key info
  if (!app_trust_data->init_policy_key(initialized_cert_size, initialized_cert)) {
    printf("Can't init policy key\n");
    return 1;
  }

  string platform_attest_file_name(data_dir);
  string measurement_file_name(data_dir);
  measurement_file_name.append(measurement_file);
  string attest_key_file_name(data_dir);
  attest_key_file_name.append(attest_key_file);

  string endorsement_cert;

  if (!app_trust_data->initialize_keystone_enclave_data(attest_key_file_name,
          measurement_file_name, platform_attest_file_name)) {
    printf("Can't init keystone enclave\n");
    return 1;
  }

  // Standard algorithms for the enclave
  string public_key_alg("rsa-2048");
  string symmetric_key_alg("aes-256-cbc-hmac-sha256");

  // Carry out operation

  printf("Entering operation\n");
  int ret = 0;
  if (operation == "cold-init") {
    printf("Cold Init...\n");
    if (!app_trust_data->cold_init(public_key_alg, symmetric_key_alg)) {
      printf("cold-init failed\n");
      ret = 1;
    }
  } else if (operation == "warm-restart") {
    if (!app_trust_data->warm_restart()) {
      printf("warm-restart failed\n");
      ret = 1;
    }

  } else if (operation == "get-certifier") {
    if (!app_trust_data->certify_me(policy_host, policy_port)) {
      printf("certification failed\n");
      ret = 1;
    }
  } else if (operation == "run-app-as-client") {
    string my_role("client");
    secure_authenticated_channel channel(my_role);

    if (!app_trust_data->warm_restart()) {
      printf("warm-restart failed\n");
      ret = 1;
      goto done;
    }

    printf("Running App as client\n");
    if (!app_trust_data->cc_auth_key_initialized_ ||
        !app_trust_data->cc_policy_info_initialized_) {
      printf("trust data not initialized\n");
      ret = 1;
      goto done;
    }

    if (!channel.init_client_ssl(server_app_host, server_app_port,
          app_trust_data->serialized_policy_cert_,
          app_trust_data->private_auth_key_,
          app_trust_data->private_auth_key_.certificate())) {
      printf("Can't init client app\n");
      ret = 1;
      goto done;
    }

  // This is the actual application code.
  client_application(channel);
  } else if (operation == "run-app-as-server") {
    if (!app_trust_data->warm_restart()) {
      printf("warm-restart failed\n");
      ret = 1;
      goto done;
    }
    printf("Running App as server\n");
    if (!server_dispatch(server_app_host, server_app_port,
                         app_trust_data->serialized_policy_cert_,
                         app_trust_data->private_auth_key_,
                         app_trust_data->private_auth_key_.certificate(),
                         server_application)) {
      ret = 1;
      goto done;
    }
  } else {
    printf("Unknown operation\n");
  }
  printf("Done");

done:
  // app_trust_data->print_trust_data();
  app_trust_data->clear_sensitive_data();
  if (app_trust_data != nullptr) {
    delete app_trust_data;
  }
  return ret;
}
