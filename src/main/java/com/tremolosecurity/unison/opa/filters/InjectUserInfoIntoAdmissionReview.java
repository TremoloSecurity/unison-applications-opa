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

import static org.apache.directory.ldap.client.api.search.FilterBuilder.*;

import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.UUID;

import com.novell.ldap.LDAPSearchResults;
import com.tremolosecurity.config.util.ConfigManager;
import com.tremolosecurity.provisioning.core.ProvisioningParams;
import com.tremolosecurity.provisioning.core.User;
import com.tremolosecurity.provisioning.core.Workflow;
import com.tremolosecurity.proxy.ProxySys;
import com.tremolosecurity.proxy.filter.HttpFilter;
import com.tremolosecurity.proxy.filter.HttpFilterChain;
import com.tremolosecurity.proxy.filter.HttpFilterConfig;
import com.tremolosecurity.proxy.filter.HttpFilterRequest;
import com.tremolosecurity.proxy.filter.HttpFilterResponse;
import com.tremolosecurity.saml.Attribute;
import com.tremolosecurity.server.GlobalEntries;
import com.tremolosecurity.unison.opa.sdk.FindUserForAdmissionReview;

import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;

import org.apache.logging.log4j.Logger;
import org.jose4j.jws.AlgorithmIdentifiers;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.jwt.JwtClaims;

/**
 * InjectUserInfoIntoAdmissionReview
 */
public class InjectUserInfoIntoAdmissionReview implements HttpFilter {

	static Logger logger = org.apache.logging.log4j.LogManager.getLogger(InjectUserInfoIntoAdmissionReview.class.getName());

	String workflowName;
	
	String userNameAttribute;
	

	String signingKey;
    List<String> attributes;
    String subAttribute;
    int minSkew;
    String issuer;
    String audience;
	
	FindUserForAdmissionReview userForReview;

	private HttpFilterConfig config;

	@Override
	public void doFilter(HttpFilterRequest request, HttpFilterResponse response, HttpFilterChain chain)
			throws Exception {
		request.getServletRequest().setAttribute("com.tremolosecurity.unison.proxy.noRedirectOnError", "com.tremolosecurity.unison.proxy.noRedirectOnError");
		if (request.getAttribute(ProxySys.MSG_BODY) != null) {
			String json = new String( (byte[]) request.getAttribute(ProxySys.MSG_BODY));
			logger.info("json:\n" + json);
			JSONParser parser = new JSONParser();
			JSONObject root = (JSONObject) parser.parse(json);
			JSONObject req = (JSONObject) root.get("request");
			JSONObject userInfo = (JSONObject) req.get("userInfo");

			String username = (String) userInfo.get("username");

			LDAPSearchResults res = GlobalEntries.getGlobalEntries().getConfigManager().getMyVD().search(GlobalEntries.getGlobalEntries().getConfigManager().getCfg().getLdapRoot(), 2, equal(this.userNameAttribute,username).toString(), new ArrayList<String>());
			if (! res.hasMore()) {
				String usernameFromReview = userForReview.whoIsUser(root, request,config);
				if (usernameFromReview != null) {
					username = usernameFromReview;
				}
			} else {
				while (res.hasMore()) res.next();
			}

			User user = new User(username);
			user.getAttribs().put(this.userNameAttribute, new Attribute(this.userNameAttribute,username));

			

			HashMap<String,Object> wfreq = new HashMap<String,Object>();
			wfreq.put(ProvisioningParams.UNISON_EXEC_TYPE, ProvisioningParams.UNISON_EXEC_SYNC);
			GlobalEntries.getGlobalEntries().getConfigManager().getProvisioningEngine().getWorkFlow(this.workflowName).executeWorkflow(user, wfreq);

			JwtClaims claims = new JwtClaims();
			claims.setIssuer(issuer);  // who creates the token and signs it
			claims.setAudience(audience); // to whom the token is intended to be sent
			claims.setExpirationTimeMinutesInTheFuture(minSkew); // time when the token will expire (10 minutes from now)
			
			claims.setGeneratedJwtId(); // a unique identifier for the token
			claims.setIssuedAtToNow();  // when the token was issued/created (now)
			claims.setNotBeforeMinutesInThePast(minSkew); // time before which the token is not yet valid (2 minutes ago)
			
			claims.setClaim("nonce", UUID.randomUUID().toString());

			

			

			claims.setSubject(user.getAttribs().get(this.subAttribute).getValues().get(0));

			for (String attributeName : this.attributes) {
				Attribute attr = user.getAttribs().get(attributeName);
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

			userInfo.put("injectedIdentity", jws.getCompactSerialization());
			

			logger.info("new json" + root.toJSONString());

			request.setAttribute(ProxySys.MSG_BODY, root.toJSONString().getBytes("UTF-8"));
		}
		chain.nextFilter(request, response, chain);

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
		this.workflowName = loadOption("workflowName", config);
		
		this.userNameAttribute = loadOption("userNameAttribute",config);

		this.issuer = loadOption("issuer", config);
        this.audience = loadOption("audience",config);
        this.minSkew = Integer.parseInt(loadOption("minSkew",config));
        this.signingKey = loadOption("signingKey", config);
        this.subAttribute = loadOption("subAttribute",config);

        this.attributes = new ArrayList<String>();

        if (config.getAttribute("attributes") != null) {
            this.attributes.addAll(config.getAttribute("attributes").getValues());
            
		}
		
		this.config = config;

		String whoamiClassName = this.loadOption("whoIsUserClassName", config);
		this.userForReview = (FindUserForAdmissionReview) Class.forName(whoamiClassName).newInstance();
		
	}

	private String buildKID(X509Certificate cert) {
		StringBuffer b = new StringBuffer();
		b.append(cert.getSubjectDN().getName()).append('-').append(cert.getIssuerDN().getName()).append('-').append(cert.getSerialNumber().toString());
		return b.toString();
	}

    
}