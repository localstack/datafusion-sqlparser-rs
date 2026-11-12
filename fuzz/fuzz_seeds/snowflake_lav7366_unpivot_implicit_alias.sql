SELECT * FROM (SELECT 1 AS a, 2 AS b) UNPIVOT (v FOR k IN (a alpha, b AS "Mixed"));
