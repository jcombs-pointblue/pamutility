/*
 * Copyright 2019 Pointblue technology LLC.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.pointblue.netiq.pam.util;

import java.io.InputStream;
import java.io.InputStreamReader;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.ssl.SSLContextBuilder;
import org.apache.http.conn.ssl.TrustStrategy;
import org.apache.http.conn.ssl.NoopHostnameVerifier;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import org.apache.http.HttpResponse;
import org.apache.http.HttpHost;

import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPut;
import org.apache.http.impl.client.BasicCredentialsProvider;
import org.apache.http.auth.AuthScope;
import org.apache.http.client.AuthCache;
import org.apache.http.client.protocol.HttpClientContext;

import org.apache.http.impl.auth.BasicScheme;
import org.apache.http.impl.client.BasicAuthCache;
import org.apache.http.auth.UsernamePasswordCredentials;
import org.apache.http.client.CredentialsProvider;
import org.apache.http.entity.StringEntity;
import org.json.simple.parser.JSONParser;
import org.json.simple.JSONObject;
import java.io.BufferedReader;
import java.io.FileReader;
import java.io.Reader;

/**
 *
 * @author jcombs
 * 
 */
public class PamCredLoader {

    /**
     * @param args the command line arguments
     *
     * fwAdminID fwAdminPW host port rootPW fwHost
     *
     *
     *
     */
    private String fwHost;
    private String fwAdmin;
    private String fwPassword;
    private String loadFile;
    private String host;
    private String port;
    private String acct;
    private String acctPW;

    //refactor to allow debug switch
    static {
       // System.setProperty("org.apache.commons.logging.Log", "org.apache.commons.logging.impl.SimpleLog");
       // System.setProperty("org.apache.commons.logging.simplelog.showdatetime", "true");
       //  System.setProperty("org.apache.commons.logging.simplelog.log.org.apache.http.wire", "DEBUG");
        //System.setProperty("org.apache.commons.logging.simplelog.log.org.apache.http", "DEBUG");
    }

    private AuthCache authCache = new BasicAuthCache();
    private HttpClientContext localContext = HttpClientContext.create();

    public static void main(String[] args) {
        PamCredLoader theOne = new PamCredLoader();

        //Parse params
        // fwhost fwAcct fwpassword file
        // fwhost fwAcct fwpassword host port acct password
        //System.out.println("args: " + args.length);
        if (args.length == 4 || args.length == 7) {
            theOne.fwHost = args[0];
            theOne.fwAdmin = args[1];
            theOne.fwPassword = args[2];

            //Set up preemptive authentication on the request
            HttpHost target = new HttpHost(theOne.fwHost, 443, "https");
            theOne.authCache.put(target, new BasicScheme());
            theOne.localContext.setAuthCache(theOne.authCache);

            if (args.length == 4) {

                theOne.loadFile = args[3];
                //open file
                try (BufferedReader br = new BufferedReader(new FileReader(theOne.loadFile))) {
                    String line;
                    //iterate file
                    while ((line = br.readLine()) != null) {
                        String[] fields = line.split(",");
                        if (fields.length == 4) {
                            theOne.host = fields[0];
                            theOne.port = fields[1];
                            theOne.acct = fields[2];
                            theOne.acctPW = fields[3];

                            theOne.provisionHost();
                        }else
                        {
                            System.out.println("Bad line in file");
                        }
                    }
                } catch (Exception ex) {
                    ex.printStackTrace();
                }

            }
            if (args.length == 7) {

                theOne.host = args[3];
                theOne.port = args[4];
                theOne.acct = args[5];
                theOne.acctPW = args[6];

                theOne.provisionHost();
            }

        } else {
            //print usage
            System.out.println("Incorrect Parameters");
            System.exit(-1);
        }

    }

    private void provisionHost() {
        String hk = getSSHKey(host, port);
        // System.out.println("Key: " + hk);
        if (hk != null) {
            String vaultID = createVault(host, port, hk);
            // System.out.println(vaultID);
            if (vaultID != null) {
                String credentialID = createPWCredential(acct, acctPW, vaultID);
            }
        } else {
            System.out.println("Failed to retrieve host key for: " + host);
        }
    }

    public String getSSHKey(String host, String port) {
        String key = null;
        String result = "";

        CloseableHttpClient client = getHttpClient();

        HttpGet get = new HttpGet("https://" + fwHost + "/rest/sshagnt/HostKey?ssh_host=" + host + "&port=" + port);

        try {

            HttpResponse response = null;

            response = client.execute(get, localContext);
            int code = response.getStatusLine().getStatusCode();
            if (code == 200) {
                InputStream inputStream = response.getEntity().getContent();

                StringBuilder textBuilder = new StringBuilder();
                Reader reader = new BufferedReader(new InputStreamReader(inputStream, "UTF-8"));
                JSONParser parser = new JSONParser();
                JSONObject returnObj = (JSONObject) parser.parse(reader);
                //System.out.println(returnObj.toJSONString());
                JSONObject keyhost = (JSONObject) returnObj.get("Host");
                return (String) keyhost.get("hkey");

            } else {
                //result = result + response.getStatusLine();
                //System.out.println(result);
                System.out.println("Get Host Key - Host: " + host + ": " + response.getStatusLine());

            }
        } catch (Exception ex) {
            ex.printStackTrace();
            System.out.println("Get Host Key - Host: " + host + ": " + ex.getMessage());

        }
        /*
        500 "Failed to retrieve host key" on bad host
        
         */

        return key;
    }

    public String createVault(String host, String port, String hostKey) {
        String result = null;
        JSONObject ssh = new JSONObject();
        ssh.put("hkey", hostKey);
        ssh.put("host", host);
        ssh.put(port, port);
        JSONObject cfg = new JSONObject();
        cfg.put("SSH", ssh);
        JSONObject vault = new JSONObject();
        vault.put("type", "ssh");
        vault.put("profile", "101");
        vault.put("name", host);
        vault.put("CFG", cfg);

        JSONObject body = new JSONObject();
        body.put("Vault", vault);
        //System.out.println(body.toJSONString());

        CloseableHttpClient client = getHttpClient();

        HttpPut put = new HttpPut("https://" + fwHost + "/rest/prvcrdvlt/Vault");

        try {

            HttpResponse response = null;
            put.setEntity(new StringEntity(body.toJSONString()));

            response = client.execute(put, localContext);
            int code = response.getStatusLine().getStatusCode();
            if (code == 200) {
                InputStream inputStream = response.getEntity().getContent();

                StringBuilder textBuilder = new StringBuilder();
                Reader reader = new BufferedReader(new InputStreamReader(inputStream, "UTF-8"));
                JSONParser parser = new JSONParser();
                JSONObject returnObj = (JSONObject) parser.parse(reader);
                //System.out.println(returnObj.toJSONString());
                JSONObject rtnVault = (JSONObject) returnObj.get("Vault");
                return (String) rtnVault.get("id");

            } else {
                System.out.println("Create Vault - Host: " + host + ": " + response.getStatusLine());
            }
        } catch (Exception ex) {
            ex.printStackTrace();
            //result = result + ex.getMessage();
            System.out.println("Create Vault - Host: " + host + ": " + ex.getMessage());

        }

        return result;
        /*
        HTTP/1.0 400 Resource with the same name already exists. Specify a different name.
         */
    }

    public String createPWCredential(String acct, String password, String vaultID) {
        String result = null;
        JSONObject pcd = new JSONObject();
        pcd.put("passwd", password);

        JSONObject credential = new JSONObject();
        credential.put("vault", vaultID);
        credential.put("account", acct);
        credential.put("type", "passwd");
        credential.put("PCD", pcd);

        JSONObject body = new JSONObject();
        body.put("Credential", credential);
        //System.out.println(body.toJSONString());

        CloseableHttpClient client = getHttpClient();

        HttpPut put = new HttpPut("https://" + fwHost + "/rest/prvcrdvlt/Credential");

        try {

            HttpResponse response = null;
            put.setEntity(new StringEntity(body.toJSONString()));

            response = client.execute(put, localContext);
            int code = response.getStatusLine().getStatusCode();
            if (code == 200) {
                InputStream inputStream = response.getEntity().getContent();

                StringBuilder textBuilder = new StringBuilder();
                Reader reader = new BufferedReader(new InputStreamReader(inputStream, "UTF-8"));
                JSONParser parser = new JSONParser();
                JSONObject returnObj = (JSONObject) parser.parse(reader);
                //System.out.println(returnObj.toJSONString());
                JSONObject rtnCredential = (JSONObject) returnObj.get("Credential");
                return (String) rtnCredential.get("id");

            } else {
                System.out.println("Create Credential - Host: " + host + ": " + response.getStatusLine());
            }
        } catch (Exception ex) {
            ex.printStackTrace();
            //result = result + ex.getMessage();
            System.out.println("Create Credential - Host: " + host + ": " + ex.getMessage());

        }

        return result;
    }

    public CloseableHttpClient getHttpClient() {
        // tracer.trace("Getting http client in client");
        CloseableHttpClient httpClient = null;       

        CredentialsProvider provider = new BasicCredentialsProvider();
        provider.setCredentials(
                AuthScope.ANY,
                new UsernamePasswordCredentials(fwAdmin, fwPassword)
        );

        try {
            httpClient = HttpClients.custom().
                    setSSLHostnameVerifier(NoopHostnameVerifier.INSTANCE).
                    setSSLContext(new SSLContextBuilder().loadTrustMaterial(null, new TrustStrategy() {
                        public boolean isTrusted(X509Certificate[] arg0, String arg1) throws CertificateException {
                            return true;
                        }
                    }).build()).setDefaultCredentialsProvider(provider).build();
        } catch (Exception e) {

            e.printStackTrace();
        }

        return httpClient;

    }

}
