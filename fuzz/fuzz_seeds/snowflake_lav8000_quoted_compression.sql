CREATE EXTERNAL FUNCTION f() RETURNS INT API_INTEGRATION = api COMPRESSION = 'deflate' AS 'https://example.invalid/f';
