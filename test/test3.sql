.echo on
PRAGMA cipher='aegis';
PRAGMA key='testkey';
SELECT COUNT(*) FROM persons;
SELECT DISTINCT lastname, firstname FROM persons WHERE city='Rom';
.q
