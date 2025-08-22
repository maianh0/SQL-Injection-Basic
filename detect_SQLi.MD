
1. Các phát hiện đối với mỗi loại db như kiểu SQL server thì có dấu hiệu gì

2. Ngoài thu thập dữ liệu từ db qua SQLi thì còn có thể làm được gì thêm 

# Phát hiện SQL Injection trên các loại CSDL

Mỗi hệ quản trị cơ sở dữ liệu (DBMS) có cú pháp và hàm riêng.  
Dưới đây là một số kỹ thuật phát hiện đặc trưng:

## MySQL
- **Tạo độ trễ (Time-based)**  
  ```sql
  SLEEP(5)
  ```
- **Gây lỗi hiển thị (Error-based)**  
  ```sql
  UPDATEXML(1, concat(0x7e, (SELECT @@version), 0x7e), 1)
  ```

## SQL Server (MSSQL)
- **Tạo độ trễ**  
  ```sql
  WAITFOR DELAY '0:0:5'
  ```
- **Gây lỗi ép kiểu**  
  ```sql
  AND 1 = CONVERT(int, 'text')
  ```

## PostgreSQL
- **Tạo độ trễ**  
  ```sql
  pg_sleep(5)
  ```
- **Gây lỗi ép kiểu**  
  ```sql
  CAST((SELECT version()) AS int)
  ```

## Oracle
- **Tạo độ trễ**  
  ```sql
  dbms_pipe.receive_message('a', 5)
  ```
- **Gây lỗi chia cho 0**  
  ```sql
  SELECT to_char(1/0) FROM dual
  ```  


# Ứng dụng SQLi ngoài việc thu thập dữ liệu

Ngoài việc lấy dữ liệu nhạy cảm, SQLi còn cho phép kẻ tấn công:

- **Bypass xác thực** → Đăng nhập không cần mật khẩu.  
- **Chèn, sửa hoặc xóa dữ liệu** → Làm thay đổi hoặc mất mát dữ liệu.  
- **Chiếm quyền điều khiển hệ thống** → Kết hợp với lỗ hổng khác để thực thi lệnh hệ điều hành.  
- **Phát hiện cấu trúc database** → Liệt kê bảng, cột, user DB.  
- **Leo thang đặc quyền** → Nếu tài khoản DB có quyền cao, có thể chiếm toàn bộ hệ thống.  
- **Tạo backdoor trong DB** → Cài đặt trigger hoặc stored procedure độc hại để duy trì truy cập.  
