/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.pointblue.netiq.pam.util;

import java.io.InputStream;
import java.io.InputStreamReader;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.ssl.SSLContextBuilder;
import org.apache.http.conn.ssl.TrustStrategy;
import org.apache.http.conn.ssl.NoopHostnameVerifier;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import org.apache.http.HttpResponse;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPut;

import org.apache.http.entity.StringEntity;
import org.json.simple.parser.JSONParser;
import org.json.simple.JSONObject;
import java.io.BufferedReader;
import java.io.Reader;

/**
 *
 * @author jcombs
 */
public class PamCredLoader
{

    /**
     * @param args the command line arguments
     * 
     * fwAdminID
     * fwAdminPW
     * host
     * port
     * rootPW
     * fwHost
     * 
     * 
     * 
     */
    
    private String fwHost;
    private String fwAdmin;
    private String fwPassword;
    
    public static void main(String[] args)
    {
        // TODO code application logic here
    }

    public String getSSHKey(String host, String port)
    {
        String key = "";
        String result ="";
        
        
         CloseableHttpClient client = getHttpClient();
        HttpGet get = new HttpGet("https://"+fwHost+"/rest/sshagnt/HostKey?ssh_host="+host+"&port="+port);
        try
        {

            
            HttpResponse response = null;

            response = client.execute(get);
            int code = response.getStatusLine().getStatusCode();
            if (code == 200 || code == 201 || code == 500)
            {
                InputStream inputStream = response.getEntity().getContent();

                StringBuilder textBuilder = new StringBuilder();
                Reader reader = new BufferedReader(new InputStreamReader(inputStream, "UTF-8"));

                int c = 0;
                while ((c = reader.read()) != -1)
                {
                    textBuilder.append((char) c);
                }

                return textBuilder.toString();

            }else
            {
                result = result+response.getStatusLine();
            }
        }
        catch (Exception ex)
        {
            ex.printStackTrace();
            result = result+ex.getMessage();
        }

        return key;
    }

    public String createVault()
    {
        String vaultID = "";

        return vaultID;
    }

    public String createPWCredential()
    {
        String credentialID = "";

        return credentialID;
    }

    public CloseableHttpClient getHttpClient()
    {
        // tracer.trace("Getting http client in client");
        CloseableHttpClient httpClient = null;
        //TODO: need to properly set http vs Https
        //httpClient = HttpClients.createDefault();
        try
        {
            httpClient = HttpClients.custom().
                    setSSLHostnameVerifier(NoopHostnameVerifier.INSTANCE).
                    setSSLContext(new SSLContextBuilder().loadTrustMaterial(null, new TrustStrategy()
                    {
                        public boolean isTrusted(X509Certificate[] arg0, String arg1) throws CertificateException
                        {
                            return true;
                        }
                    }).build()).build();
        }
        catch (Exception e)
        {

            e.printStackTrace();
            //tracer.trace(e.toString());
        }

        return httpClient;

    }

}
