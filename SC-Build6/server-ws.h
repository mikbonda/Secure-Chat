/*******************************************************************
 * Header file for server-ws.h
 *******************************************************************/

int AuthenticateClient(int client);

// certificates 
int SendServerCertificateBundle(int client, const char *bundle_file);


