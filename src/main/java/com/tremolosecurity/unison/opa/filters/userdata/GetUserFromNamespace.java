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

package com.tremolosecurity.unison.opa.filters.userdata;

import java.io.IOException;

import com.tremolosecurity.provisioning.util.HttpCon;
import com.tremolosecurity.proxy.filter.HttpFilterConfig;
import com.tremolosecurity.proxy.filter.HttpFilterRequest;
import com.tremolosecurity.server.GlobalEntries;
import com.tremolosecurity.unison.opa.sdk.FindUserForAdmissionReview;
import com.tremolosecurity.unison.openshiftv3.OpenShiftTarget;

import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;

/**
 * GetUserFromNamespace
 */
public class GetUserFromNamespace implements FindUserForAdmissionReview{

	@Override
	public String whoIsUser(JSONObject admissionReviewRoot, HttpFilterRequest request, HttpFilterConfig config)
			throws Exception {
        
        String targetName = config.getAttribute("targetName").getValues().get(0);
        String annotationName = config.getAttribute("annotationName").getValues().get(0);

        JSONObject req = (JSONObject) admissionReviewRoot.get("request");

        String namespace = (String) req.get("namespace");

        OpenShiftTarget os = (OpenShiftTarget) GlobalEntries.getGlobalEntries().getConfigManager().getProvisioningEngine().getTarget(targetName).getProvider();
        
        StringBuilder url = new StringBuilder("/api/v1/namespaces/").append(namespace);

        HttpCon http = null;
        try {
            http = os.createClient();
            String json = os.callWS(os.getAuthToken(), http, url.toString());
            JSONParser parser = new JSONParser();
            JSONObject root = (JSONObject) parser.parse(json);
            JSONObject metadata = (JSONObject) root.get("metadata");
            JSONObject annotations = (JSONObject) metadata.get("annotations");
            String userName = (String) annotations.get(annotationName);
            return userName;
        } catch (Exception e) {
			throw new Exception("Could not load service account token names",e);
		} finally {
            if (http != null) {
				try {
					http.getHttp().close();
				} catch (IOException e) {
					
				}

				http.getBcm().shutdown();
			}
        }

	}

    
}