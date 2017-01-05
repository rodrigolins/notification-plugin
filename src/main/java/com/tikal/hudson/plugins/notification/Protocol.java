/**
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * <p>
 * http://www.apache.org/licenses/LICENSE-2.0
 * <p>
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.tikal.hudson.plugins.notification;


import java.io.IOException;
import java.io.OutputStream;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.HttpURLConnection;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.MalformedURLException;
import java.net.Proxy;
import java.net.Socket;
import java.net.SocketAddress;
import java.net.URL;

import javax.xml.bind.DatatypeConverter;


public enum Protocol {

    UDP {
        @Override
        protected void send(String url, byte[] data, int timeout, boolean isJson) throws IOException {
            HostnamePort hostnamePort = HostnamePort.parseUrl(url);
            DatagramSocket socket = new DatagramSocket();
            DatagramPacket packet = new DatagramPacket(data, data.length, InetAddress.getByName(hostnamePort.hostname), hostnamePort.port);
            socket.send(packet);
        }
    },
    TCP {
        @Override
        protected void send(String url, byte[] data, int timeout, boolean isJson) throws IOException {
            HostnamePort hostnamePort = HostnamePort.parseUrl(url);
            SocketAddress endpoint = new InetSocketAddress(InetAddress.getByName(hostnamePort.hostname), hostnamePort.port);
            Socket socket = new Socket();
            socket.setSoTimeout(timeout);
            socket.connect(endpoint, timeout);
            OutputStream output = socket.getOutputStream();
            output.write(data);
            output.flush();
            output.close();
        }
    },
    HTTP {
        @Override
        protected void send(String url, byte[] data, int timeout, boolean isJson) throws IOException {

            URL targetUrl = new URL(url);
            if (!targetUrl.getProtocol().startsWith("http")) {
                throw new IllegalArgumentException("Not an http(s) url: " + url);
            }

            // Verifying if the http_proxy or HTTP_PROXY is available
            URL proxyURL = null;

            // Verifying http_proxy URL
            String http_proxyURL = System.getenv().get("http_proxy");

            if (http_proxyURL != null && http_proxyURL.length() > 0) {
                proxyURL = new URL(http_proxyURL);
            }

            // Verifying HTTP_PROXY URL
            String HTTP_PROXYURL = System.getenv("HTTP_PROXY");

            if (HTTP_PROXYURL != null && HTTP_PROXYURL.length() > 0) {
                proxyURL = new URL(HTTP_PROXYURL);
            }

            // Verifying https_proxy URL
            String https_proxyURL = System.getenv("https_proxy");

            if (https_proxyURL != null && https_proxyURL.length() > 0) {
                proxyURL = new URL(https_proxyURL);
            }

            // Verifying HTTP_PROXY URL
            String HTTPS_PROXYURL = System.getenv("HTTPS_PROXY");

            if (HTTPS_PROXYURL != null && HTTPS_PROXYURL.length() > 0) {
                proxyURL = new URL(HTTPS_PROXYURL);
            }

            // Verifying no_proxy URL
            boolean no_proxy = false;

            String no_proxyURL = System.getenv("no_proxy");

            if (no_proxyURL != null && no_proxyURL.length() > 0) {
                System.out.println("no_proxyURL = " + no_proxyURL);
                final String[] excludedURLS = no_proxyURL.split(",");
                for (String excludedURL : excludedURLS) {
                    // The variable no_proxy handles the suffixes.
                    if (targetUrl.getHost().endsWith(excludedURL.replaceFirst("^(\\*.|\\*|\\.)", ""))) {
                        no_proxy = true;
                        System.out.println("excludedURL = " + excludedURL);
                    }
                }
            }

            // Verifying NO_PROXY URL
            String NO_PROXYURL = System.getenv("NO_PROXY");

            if (NO_PROXYURL != null && NO_PROXYURL.length() > 0) {
                System.out.println("NO_PROXYURL = " + NO_PROXYURL);
                final String[] excludedURLS = NO_PROXYURL.split(",");
                for (String excludedURL : excludedURLS) {
                    // The variable no_proxy handles the suffixes.
                    if (targetUrl.getHost().endsWith(excludedURL.replaceFirst("^(\\*.|\\*|\\.)", ""))) {
                        no_proxy = true;
                        System.out.println("excludedURL = " + excludedURL);
                    }
                }
            }
            System.out.println("PROXY URL: "+ proxyURL);
            System.out.println("TARGET URL: " + targetUrl);
            System.out.println("NO_PROXY: " + no_proxy);

            HttpURLConnection connection = null;
            if (proxyURL == null || no_proxy) {
                System.out.println("No proxy or no_proxy/NO_PROXY configuration was found");
                connection = (HttpURLConnection) targetUrl.openConnection(Proxy.NO_PROXY);
            } else {
                // Proxy connection to the address provided

                // Test for HTTP or http proxy
                if(proxyURL.getProtocol().equals("http")) {
                    System.out.println("Using http/HTTP proxy");
                    final int proxyPort = proxyURL.getPort() > 0 ? proxyURL.getPort() : 80;
                    Proxy proxy = new Proxy(Proxy.Type.HTTP, new InetSocketAddress(proxyURL.getHost(), proxyPort));
                    connection = (HttpURLConnection) targetUrl.openConnection(proxy);
                }
                // Test for HTTPS of https proxy
                else if(proxyURL.getProtocol().equals("https")) {
                    System.out.println("Using https/HTTPS proxy");
                    final int proxyPort = proxyURL.getPort() > 0 ? proxyURL.getPort() : 443;
                    Proxy proxy = new Proxy(Proxy.Type.HTTP, new InetSocketAddress(proxyURL.getHost(), proxyPort));
                    connection = (HttpURLConnection) targetUrl.openConnection(proxy);
                }
                // If not HTTP or HTTPS
                else {
                    throw new IllegalArgumentException("Not an http(s) url: " + proxyURL);
                }
            }

            connection.setRequestProperty("Content-Type", String.format("application/%s;charset=UTF-8", isJson ? "json" : "xml"));
            String userInfo = targetUrl.getUserInfo();
            if (null != userInfo) {
                String b64UserInfo = DatatypeConverter.printBase64Binary(userInfo.getBytes());
                String authorizationHeader = "Basic " + b64UserInfo;
                connection.setRequestProperty("Authorization", authorizationHeader);
            }
            connection.setFixedLengthStreamingMode(data.length);
            connection.setDoInput(true);
            connection.setDoOutput(true);
            connection.setConnectTimeout(timeout);
            connection.setReadTimeout(timeout);
            connection.connect();
            try {
                OutputStream output = connection.getOutputStream();
                try {
                    output.write(data);
                    output.flush();
                } finally {
                    output.close();
                }
            } finally {
                // Follow an HTTP Temporary Redirect if we get one,
                //
                // NB: Normally using the HttpURLConnection interface, we'd call
                // connection.setInstanceFollowRedirects(true) to enable 307 redirect following but
                // since we have the connection in streaming mode this does not work and we instead
                // re-direct manually.
                if (307 == connection.getResponseCode()) {
                    String location = connection.getHeaderField("Location");
                    connection.disconnect();
                    send(location, data, timeout, isJson);
                } else {
                    connection.disconnect();
                }
            }
        }

        @Override
        public void validateUrl(String url) {
            try {
                // noinspection ResultOfObjectAllocationIgnored
                new URL(url);
            } catch (MalformedURLException e) {
                throw new RuntimeException(String.format("%sUse http://hostname:port/path for endpoint URL",
                        isEmpty(url) ? "" : "Invalid URL '" + url + "'. "));
            }
        }
    };


    protected abstract void send(String url, byte[] data, int timeout, boolean isJson) throws IOException;

    public void validateUrl(String url) {
        try {
            HostnamePort hnp = HostnamePort.parseUrl(url);
            if (hnp == null) {
                throw new Exception();
            }
        } catch (Exception e) {
            throw new RuntimeException(String.format("%sUse hostname:port for endpoint URL",
                    isEmpty(url) ? "" : "Invalid URL '" + url + "'. "));
        }
    }

    private static boolean isEmpty(String s) {
        return ((s == null) || (s.trim().length() < 1));
    }
}
