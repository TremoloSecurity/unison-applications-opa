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

package com.tremolosecurity.unison.opa.tasks;

import java.io.IOException;
import java.util.Map;

import com.tremolosecurity.config.util.ConfigManager;
import com.tremolosecurity.provisioning.core.ProvisioningException;
import com.tremolosecurity.provisioning.core.User;
import com.tremolosecurity.provisioning.core.WorkflowTask;
import com.tremolosecurity.provisioning.util.CustomTask;
import com.tremolosecurity.provisioning.util.HttpCon;
import com.tremolosecurity.saml.Attribute;
import com.tremolosecurity.server.GlobalEntries;
import com.tremolosecurity.unison.openshiftv3.OpenShiftTarget;

import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.apache.logging.log4j.Logger;

public class LoadServiceAccountTokenNames implements CustomTask {

    static Logger logger = org.apache.logging.log4j.LogManager.getLogger(LoadServiceAccountTokenNames.class.getName());

    String namespace;
    String serviceAccountName;
    String target;
    String prefix;

    transient WorkflowTask task;
	@Override
	public void init(WorkflowTask task, Map<String, Attribute> params) throws ProvisioningException {
        this.task = task;
        this.namespace = params.get("namespace").getValues().get(0);
        this.target = params.get("target").getValues().get(0);
        this.serviceAccountName = params.get("serviceAccountName").getValues().get(0);
        this.prefix = params.get("prefix").getValues().get(0);
	}

	@Override
	public void reInit(WorkflowTask task) throws ProvisioningException {
		this.task = task;
	}

	@Override
	public boolean doTask(User user, Map<String, Object> request) throws ProvisioningException {
        OpenShiftTarget os = (OpenShiftTarget) GlobalEntries.getGlobalEntries().getConfigManager().getProvisioningEngine().getTarget(this.target).getProvider();
        StringBuilder sb = new StringBuilder();
        String localNamespace = task.renderTemplate(this.namespace, request);
        
        

        
        String localServiceAccountName = task.renderTemplate(this.serviceAccountName, request);
        
        sb.append("/api/v1/namespaces/").append(localNamespace).append("/secrets");
        
        HttpCon http = null;
        try {
            http = os.createClient();
            String json = os.callWS(os.getAuthToken(), http, sb.toString());
            
            JSONParser parser  = new JSONParser();
            JSONObject root = (JSONObject) parser.parse(json);
            JSONArray items = (JSONArray) root.get("items");
            for (Object o : items) {
                JSONObject item = (JSONObject) o;
                JSONObject metadata = (JSONObject) item.get("metadata");
                if (metadata == null) {
                    continue;
                }

                JSONObject annotations = (JSONObject) metadata.get("annotations");
                
                if (annotations == null) {
                    continue;
                }
                
                String serviceAccountForSecret = (String) annotations.get("kubernetes.io/service-account.name");
                
                if (serviceAccountForSecret == null) {
                    continue;
                }

                if (serviceAccountForSecret.equals(localServiceAccountName)) {
                    String tokenName = (String) metadata.get("name");
                    String attrName = tokenName.substring(localServiceAccountName.length() + 1,tokenName.lastIndexOf('-'));
                    sb.setLength(0);
                    sb.append(prefix).append('-').append(attrName);
                    Attribute attr = new Attribute(sb.toString(),tokenName);
                    user.getAttribs().put(attr.getName(), attr);
                }
                

            }
        } catch (Exception e) {
			throw new ProvisioningException("Could not load service account token names",e);
		} finally {
            if (http != null) {
				try {
					http.getHttp().close();
				} catch (IOException e) {
					
				}

				http.getBcm().shutdown();
			}
        }

        return true;

	}

}