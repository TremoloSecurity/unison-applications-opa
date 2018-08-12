//    Copyright 2018 Tremolo Security, Inc.
// 
//    Licensed under the Apache License, Version 2.0 (the "License");
//    you may not use this file except in compliance with the License.
//    You may obtain a copy of the License at
// 
//        http://www.apache.org/licenses/LICENSE-2.0
// 
//    Unless required by applicable law or agreed to in writing, software
//    distributed under the License is distributed on an "AS IS" BASIS,
//    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//    See the License for the specific language governing permissions and
//    limitations under the License.


package com.tremolosecurity.unison.opa.filters;

import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

import com.tremolosecurity.proxy.auth.AuthInfo;
import com.tremolosecurity.proxy.filter.HttpFilter;
import com.tremolosecurity.proxy.filter.HttpFilterChain;
import com.tremolosecurity.proxy.filter.HttpFilterConfig;
import com.tremolosecurity.proxy.filter.HttpFilterRequest;
import com.tremolosecurity.proxy.filter.HttpFilterResponse;
import com.tremolosecurity.proxy.util.ProxyConstants;
import com.tremolosecurity.saml.Attribute;
import com.tremolosecurity.server.GlobalEntries;
import com.tremolosecurity.provisioning.core.User;
import com.tremolosecurity.proxy.auth.AuthController;

import org.apache.logging.log4j.Logger;
import org.jose4j.jws.AlgorithmIdentifiers;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.jwt.JwtClaims;

/**
 * GenerateJWT
 */
public class GenerateJWT implements HttpFilter {

    static Logger logger = org.apache.logging.log4j.LogManager.getLogger(GenerateJWT.class.getName());

    String signingKey;
    List<String> attributes;
    String subAttribute;
    int minSkew;
    String issuer;
    String audience;
    String requestAttributeName;


	@Override
	public void doFilter(HttpFilterRequest request, HttpFilterResponse response, HttpFilterChain chain)
			throws Exception {
        
        JwtClaims claims = new JwtClaims();
        claims.setIssuer(issuer);  // who creates the token and signs it
        claims.setAudience(audience); // to whom the token is intended to be sent
        claims.setExpirationTimeMinutesInTheFuture(minSkew); // time when the token will expire (10 minutes from now)
        
        claims.setGeneratedJwtId(); // a unique identifier for the token
        claims.setIssuedAtToNow();  // when the token was issued/created (now)
        claims.setNotBeforeMinutesInThePast(minSkew); // time before which the token is not yet valid (2 minutes ago)
        
        claims.setClaim("nonce", UUID.randomUUID().toString());

        User userData = (User) request.getAttribute(this.requestAttributeName);

        

        claims.setSubject(userData.getAttribs().get(this.subAttribute).getValues().get(0));

        for (String attributeName : this.attributes) {
            Attribute attr = userData.getAttribs().get(attributeName);
            if (attr != null) {
                if (attr.getValues().size() == 1) {
                    claims.setStringClaim(attributeName, attr.getValues().get(0));
                } else {
                    claims.setStringListClaim(attributeName, attr.getValues());
                }
            }
        }

        JsonWebSignature jws = new JsonWebSignature();
        jws.setPayload(claims.toJson());
        jws.setKey(GlobalEntries.getGlobalEntries().getConfigManager().getPrivateKey(this.signingKey));
        jws.setKeyIdHeaderValue(this.buildKID(GlobalEntries.getGlobalEntries().getConfigManager().getCertificate(this.signingKey)));
        jws.setAlgorithmHeaderValue(AlgorithmIdentifiers.RSA_USING_SHA256);

        StringBuilder az = new StringBuilder();
        az.append("Bearer ").append(jws.getCompactSerialization());
        if (request.getHeader("Authorization") != null) {
            request.removeHeader("Authorization");
        }

        logger.info("Token : '" + az + "'");

        request.addHeader(new Attribute("Authorization",az.toString()));

        chain.nextFilter(request, response, chain);

    }
    
    private String buildKID(X509Certificate cert) {
		StringBuffer b = new StringBuffer();
		b.append(cert.getSubjectDN().getName()).append('-').append(cert.getIssuerDN().getName()).append('-').append(cert.getSerialNumber().toString());
		return b.toString();
	}

	@Override
	public void filterResponseText(HttpFilterRequest request, HttpFilterResponse response, HttpFilterChain chain,
			StringBuffer data) throws Exception {
		
	}

	@Override
	public void filterResponseBinary(HttpFilterRequest request, HttpFilterResponse response, HttpFilterChain chain,
			byte[] data, int length) throws Exception {
		
    }
    
    private String loadOption(String name, HttpFilterConfig cfg) throws Exception {
		if (cfg.getAttribute(name) == null) {
			throw new Exception(name + " is required");
		} else {
			String val = cfg.getAttribute(name).getValues().get(0);
			logger.info("Config " + name + "='" + val + "'");
			

			return val;
		}
	}

	@Override
	public void initFilter(HttpFilterConfig config) throws Exception {
        this.issuer = loadOption("issuer", config);
        this.audience = loadOption("audience",config);
        this.minSkew = Integer.parseInt(loadOption("minSkew",config));
        this.signingKey = loadOption("signingKey", config);
        this.subAttribute = loadOption("subAttribute",config);

        this.attributes = new ArrayList<String>();

        if (config.getAttribute("attributes") != null) {
            this.attributes.addAll(config.getAttribute("attributes").getValues());
            
        }

        this.requestAttributeName = loadOption("requestAttributeName", config);
	}

	

    
}