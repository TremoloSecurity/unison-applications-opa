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

import com.tremolosecurity.provisioning.core.User;
import com.tremolosecurity.proxy.filter.HttpFilter;
import com.tremolosecurity.proxy.filter.HttpFilterChain;
import com.tremolosecurity.proxy.filter.HttpFilterConfig;
import com.tremolosecurity.proxy.filter.HttpFilterRequest;
import com.tremolosecurity.proxy.filter.HttpFilterResponse;
import com.tremolosecurity.saml.Attribute;

import org.apache.logging.log4j.Logger;

/**
 * SetUserObject
 */
public class SetUserObject implements HttpFilter {

    static Logger logger = org.apache.logging.log4j.LogManager.getLogger(SetUserObject.class.getName());

    String userName;
    String requestAttributeName;
    String userNameAttribute;

	@Override
	public void doFilter(HttpFilterRequest request, HttpFilterResponse response, HttpFilterChain chain)
			throws Exception {
        User user = new User(userName);
        user.getAttribs().put(this.userNameAttribute, new Attribute(this.userNameAttribute,this.userName));
        request.setAttribute(this.requestAttributeName, user);
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

	@Override
	public void initFilter(HttpFilterConfig config) throws Exception {
        this.requestAttributeName = loadOption("requestAttributeName", config);
        this.userName = loadOption("userName", config);
        this.userNameAttribute = loadOption("userNameAttribute",config);
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

    
}