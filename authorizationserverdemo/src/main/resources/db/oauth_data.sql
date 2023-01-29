INSERT INTO oauth_client_details
(client_id, client_secret, scope, authorized_grant_types,
 web_server_redirect_uri, authorities, access_token_validity,
 refresh_token_validity, additional_information, autoapprove)
VALUES
    ('clientapp', '112233', 'read_userinfo,read_contacts',
     'password,authorization_code,refresh_token', 'http://127.0.0.1:9090/login', null, 3600, 864000, null, true);
-- 注意！这条记录的 web_server_redirect_uri 字段，我们设置为 http://127.0.0.1:9090/login，这是稍后我们搭建的 XXX 系统的回调地址。
