# SQL-Injection-Basic

## Người thực hiện: Mai Anh
## Cập nhật: 04/08/2025 
1. Biết các phát hiện các trường hợp SQL INJECTION
2. Hiểu được nguyên nhân gây ra lỗi và tìm ra cách khai thác chi tiết
3. Biết được các lỗi từ các câu truy vấn phổ biến
4. Biết được các khắc phục lỗ hổng
5. Thống kê một số wordlist payload liên quan đến SQL INJECTION

SQL Injection (SQLI) là một lỗ hổng bảo mật web cho phép kẻ tấn công can thiệp vào các truy vấn mà ứng dụng thực hiện vào cơ sở dữ liệu của nó. Điều này có thể cho phép kẻ tấn công xem dữ liệu mà họ thường không thể truy xuất. Bao gồm dữ liệu thuộc về người dùng khác hoặc bất kỳ dữ liệu nào khác mà ứng dụng có thể truy cập. Trong nhiều trường hợp, kẻ tấn công có thể sửa đổi hoặc xóa dữ liệu này, gây ra những thay đổi liên tục đối với nội dung hoặc hành vi của ứng dụng.

## 1. Cách phát hiện lỗ hổng SQL Injection

Để phát hiện SQL Injection thủ công, mình cần thử từng điểm nhập trong ứng dụng một cách có hệ thống. Cách làm thường là:

- **Gửi dấu nháy đơn `'`** vào các ô nhập rồi xem ứng dụng có lỗi hay phản hồi lạ không.
- **Thử một số cú pháp SQL** để so sánh xem khi mình nhập giá trị giống ban đầu với giá trị khác thì phản hồi của web có khác nhau không.
- **Dùng các điều kiện dạng boolean** như `OR 1=1` (đúng) và `OR 1=2` (sai), rồi so sánh kết quả trả về để xem có điểm bất thường gì không.
- **Gửi payload có chứa câu lệnh gây delay** (làm chậm) như `SLEEP(5)` rồi xem phản hồi của server có bị chậm lại không → nếu có thì có khả năng là bị SQLi.
- **Dùng các payload OAST** để tạo ra tương tác mạng ngoài luồng, nếu có tương tác xảy ra thì có thể ứng dụng đang bị dính lỗi SQLi kiểu out-of-band.

## 2. Nguyên nhân gây ra lỗi và tìm ra cách khai thác chi tiết
SQL Injection có nhiều dạng khác nhau tùy vào cách ứng dụng xử lý dữ liệu đầu vào. Dưới đây là một số ví dụ phổ biến mà mình thường thấy:
#### Lấy dữ liệu bị ẩn (Retrieving hidden data):  
  Đây là khi mình sửa lại câu lệnh SQL để lấy thêm dữ liệu mà bình thường không hiển thị ra, ví dụ như xem thông tin của người dùng khác.
Lab: SQL injection vulnerability in WHERE clause allowing retrieval of hidden data  
- Trong bài lab này, khai thác lỗi SQL Injection nằm ở phần điều kiện `WHERE` để **bỏ qua điều kiện lọc sản phẩm đã phát hành**, từ đó lấy ra tất cả sản phẩm.

**Payload được sử dụng:**

```sql
' OR 1=1--
```

**URL sau khi chèn payload:**
```
https://insecure-website.com/filter?category=' OR 1=1--
```
**Truy vấn SQL sau khi bị chèn:**

```sql
SELECT * FROM products WHERE category = '' OR 1=1--' AND released = 1
```

**Giải thích:**
- `OR 1=1`: điều kiện **luôn đúng**, nên truy vấn sẽ lấy toàn bộ dữ liệu trong bảng.
- `--`: là cú pháp **comment** trong SQL → giúp **bỏ qua phần còn lại của truy vấn** (`AND released = 1`).
- Kết quả là **tất cả sản phẩm, bao gồm cả những sản phẩm chưa phát hành**, sẽ được hiển thị ra giao diện.

 <img width="1867" height="966" alt="image" src="https://github.com/user-attachments/assets/455d3df3-4b37-48a0-ab1e-0a234e2077d4" />
 <img width="1503" height="919" alt="image" src="https://github.com/user-attachments/assets/18ccd4b4-4155-459f-8a61-17062011e29f" />


> **Kết luận**: Với payload đơn giản, mình đã bypass được điều kiện lọc `released = 1` và hiển thị được toàn bộ sản phẩm. Điều này chứng minh ứng dụng dễ bị khai thác nếu không xử lý đầu vào người dùng cẩn thận.

#### Thay đổi logic ứng dụng (Subverting application logic):  
  Ta có thể chèn thêm câu lệnh vào để thay đổi cách ứng dụng xử lý logic, ví dụ đăng nhập mà không cần mật khẩu đúng.
  - Lab: SQL injection vulnerability allowing login bypass
    Để vượt qua xác thực, ta sử dụng payload administrator'-- trong trường "Username", để mật khẩu bất kì ở ô "Password" vì ô được ràng buộc để không được bỏ trống, và nhấn "Log in".
    
    <img width="1864" height="875" alt="image" src="https://github.com/user-attachments/assets/e0e327d7-6018-491d-9393-cb6987ee16f1" />
    
    Ký tự -- comment phần kiểm tra mật khẩu, khiến truy vấn SQL chỉ kiểm tra username và bỏ qua phần password, cho phép đăng nhập thành công với vai trò "administrator".
    
    <img width="1862" height="878" alt="image" src="https://github.com/user-attachments/assets/86f4c684-64af-4632-8420-de1a071016aa" />

    >**Kết quả**: Truy cập được tài khoản admin mà không cần mật khẩu

#### Tấn công bằng UNION (UNION attacks):  
Khi một ứng dụng bị lỗ hổng SQL injection và kết quả của truy vấn được trả về trong phản hồi của ứng dụng, có thể dùng từ khóa UNION để lấy dữ liệu từ các bảng khác trong cơ sở dữ liệu.
**Lab: SQL injection UNION attack, determining the number of columns returned by the query**
  - Xác định số lượng cột của câu truy vấn ban đầu thông qua kỹ thuật UNION-based SQL Injection, bằng cách: Chèn thêm các giá trị NULL cho đến khi không còn lỗi xuất hiện.
  - Truy cập Burp Suite và chặn request
    + Truy cập lab và chọn một bộ lọc category (danh mục).
    + Dùng Burp Suite để Intercept request gửi đến server khi chọn category.Chuột phải vào request → chọn "Send to Repeater".
    <img width="1919" height="805" alt="image" src="https://github.com/user-attachments/assets/76e741ac-b0ab-4da2-b7f1-b395da985a53" />

    + Chuyển qua tab Repeater, sẽ thấy URL như:
      ```
      GET /filter?category=Gifts HTTP/1.1
      ```
  - Sửa category để thêm payload SQLi và gửi đi để ktra:
    ```
    GET /filter?category=Accessories'+UNION+SELECT+NULL-- HTTP/1.1
    ```
    <img width="1537" height="711" alt="image" src="https://github.com/user-attachments/assets/d0cc79aa-f676-4c88-acdf-6e9bea798108" />
    > Tiếp tục tăng NULL nếu bị lỗi.
    
    <img width="1480" height="716" alt="image" src="https://github.com/user-attachments/assets/36e7465e-f0b4-4247-9fa4-3578b4471383" />
    
  - Khi response không còn lỗi và bạn thấy "null" xuất hiện trong nội dung HTML → tức là số lượng NULL đúng với số cột.
  - Số lượng NULL trong payload lúc này chính là số cột trong query.
    <img width="1898" height="949" alt="image" src="https://github.com/user-attachments/assets/d1ee5a78-9195-467b-a4ea-e4eaae118a3a" />

#### SQL Injection mù (Blind SQL Injection):  
  SQL injection mù xảy ra khi một ứng dụng tồn tại lỗ hổng SQL injection, nhưng phản hồi HTTP của nó không chứa kết quả của truy vấn SQL liên quan hoặc chi tiết lỗi từ cơ sở dữ liệu.
- **Khai thác blind SQL injection bằng cách kích hoạt phản hồi có điều kiện**
  Truy vấn này có lỗ hổng SQL injection, nhưng kết quả không trả về cho người dùng. Tuy nhiên, ứng dụng sẽ thay đổi hành vi tùy vào việc truy vấn có trả kết quả hay không.
  + Nếu TrackingId hợp lệ → truy vấn trả kết quả → hiển thị thông báo "Welcome back".
  + Nếu TrackingId không hợp lệ → không hiển thị thông báo đó.
> Dựa vào sự khác biệt này, ta có thể khai thác SQLi mù bằng cách chèn điều kiện để kiểm tra từng thông tin.
- **SQL Injection dựa trên lỗi (Error-based SQL injection)**
Là kỹ thuật lợi dụng thông báo lỗi từ cơ sở dữ liệu để trích xuất hoặc suy luận dữ liệu nhạy cảm, kể cả trong trường hợp mù.
  + Có thể tạo lỗi dựa vào điều kiện boolean.
  + Hoặc tạo lỗi hiển thị trực tiếp dữ liệu truy vấn, biến blind SQLi thành SQLi hiển thị.
> Nếu ứng dụng trả phản hồi khác nhau khi có lỗi, suy ra điều kiện đúng/sai.
- **Trích xuất dữ liệu nhạy cảm qua lỗi chi tiết**
- **Khai thác blind SQL injection bằng cách kích hoạt độ trễ (Time Delay)**
  ```
  '; IF (1=2) WAITFOR DELAY '0:0:10'--
  '; IF (1=1) WAITFOR DELAY '0:0:10'--
  ```
