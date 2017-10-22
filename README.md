一、网站常见漏洞

	1.不完善的身份验证措施（攻击者破解保护性不强的密码，发动暴力破解和完全避开登录）

	2.不完全的访问控制措施（攻击者可以查看其它用户保存在服务器中的信息，或者执行管理员特权操作）

	3.SQL注入（干扰应用程序与后端数据库的交互活动，或者在数据库服务器上执行命令）

	4.跨站点脚本（攻击者攻击应用程序的其他用户，访问其信息，代表他们执行操作）

	5.信息泄露（程序泄露敏感信息，攻击者利用这些敏感信息通过有缺陷的错误处理或其他行为攻击应用程序）

二、核心安全问题

	1.用户可以提交任意输入

	2.用户可以干预客户端和服务器传送的所有数据，包括请求参数，Cookie和HTTP信息头。可以轻易避开客户端执行的任何安全控件，如输入确认验证。

	3.用户可以按任何顺序发送请求，并可在应用程序要求之外的不同阶段不止一次的提交或根本不提交参数。用户的操作可能与开发人员对用户和应用程序交互方式做出的任何假设完全不同。



三、核心防御机制

	a.处理用户访问
		在通常情况下，用户分为匿名用户，普通用户，管理用户。应用程序使用三层相互关联的安全机制处理用户访问
		1.身份验证
		2.会话管理
		3.访问控制

	b处理用户输入
		对应用程序功能的输入，防止错误输入造成不良行为
		1.输入的多样性
		2.输入的处理方法
			拒绝已知的不良输入
			接受已知的不良输入
			净化
			安全数据处理
			语法检查
		3.边界确认
		4.多不确定与规范

	c.处理攻击者
		确保应用程序在成为直接攻击目标时能够正常运转，并采取适当的防御与攻击措施挫败攻击者。
		1.处理错误
			使用Try  Catch捕获异常
		2.维护审计日志
			记录与身份验证相关的事件，如成功或失败的登录，信息修改等
			记录关键交易，如信用卡支付或者转账
			任何包含已知攻击字符串，公然表明恶意意图的请求
		3.向管理员发出警报
		4.应对攻击

	d.管理应用程序


四、客户端数据请求的攻击与防护
	
	客户端提交数据
		1.通过隐藏表单字段传递数据
			前端代码如下:
				<form action="order.jsp" method="post">
					名称：苹果
					数量：<input type="number" name="quantity">
					<input type="hidden" name="price" value="12">
					<input type="submit" value="submit">
				</form>
			后台获取数据代码:
				int quantity = Integer.parseInt(request.getParameter("quantity"));
				float price = Float.parseFloat(request.getParameter("price"));
				...

		2.HTTP cookie
			服务器发送给客户端商品价格的cookie值,提交的时候提交这个cookie值(可能是进行加密的价格函数,但是仍然不能够完全杜绝攻击)

		3.URL参数
			在我们购买产品的时候,如果采用GET方式传值,那么我们可以在地址栏看到www.example.com/order.jsp?product=tofu&price=12.2&quantity=12

	攻击方式:
		以上的操作,我们都可以使用代理服务器工具攻击,例如:Burp Proxy或WebScarab或Paros可以拦截应用程序发布和收到的每一个请求和响应。并且可以对拦截的请求和响应进行修改。所以对于上面的请求,我们可以修改商品的价格,从而达到效果。对于Cookie我们可以获取到服务器传递给我们的值,如果涉及到其他敏感信息,我们在修改以后也可以达到我们的效果。

	防御方式:
		通过代理服务器,我们可以拦截和修改客户端的请求和服务器的响应,所以我们需要假设客户端提交的数据都是不值得信任的。
		1.敏感数据不通过客户端的请求获得,例如商品的价格,商品的折扣。我们应该通过产品编码在数据库中进行查询或者在后台生成session进行验证。



五、验证机制的攻击与防护

	a.注册登录
		很多web程序注册的时候没有对用户的密码强度进行控制,导致用户使用过于简单的密码进行登录。

		攻击方式:
			暴力攻击,因为密码强度不大,很轻松就可以暴力攻击成功.使用工具Burp Intruder就可以实现在每分钟发出
			上千次登录尝试。

		防护措施:
			1.强制用户在注册的时候使用高强度的密码。
			2.我们可以设置一个记录登录次数的session值如果是cookie,那么通过可以代理服务器进行修改),当登录次数到底
			上限值的时候，我们拒绝其登录。
			3.登录的时候不只是输入用户名和密码,此外也要求输入其他信息,例如登录的时候进行短信验证,或者通过电子邮件
			发送具有时间限制的验证码。

	b.找回密码验证

		攻击方式：通过枚举法,找到用户名。在进行答案验证的时候通过提示符,通过枚举找出答案
		防护措施：防止枚举,通过记录登陆次数的方式。

	c.可预测的用户名或密码
		一些应用程序根据某种特定的顺序,自动生成用户名或者密码。

		攻击方式:
			如果攻击者获取到了一个用户名或者密码,通过枚举法可以较快进行攻击,导致获取到全部的用户名和密码

		防护措施:
			1.登录的时候加上唯一验证符,例如手机验证码。
			2.防止用户枚举操作。设置一个记录登录次数的session值如果是cookie,那么通过可以代理服务器进行修改),当登录次数到底上限值的时候，我们拒绝其登录。


六、访问控制攻击和防护
	每个访问者被分类为不同的角色,只能够访问允许自己访问的内容。如果用户可以访问自己不应该访问的内容,那么该网站就存在访问控制漏洞。

	常见漏洞
		1.通过URL跳转到管理员界面
			<script>
				var isAdmin = false;
				if(isAdmin) {
					window.location = "www.example.com/admin.jsp";
				}
			</script>

			或者在后台进行页面重定向的方式跳转
			response.sendRedirect("/index.jsp?admin=true");

			攻击方式:
				攻击者只需要看一下JavaScript源码,就知道管理员使用的url,并尝试访问他们。如果是第二种方式,在一些离职的管理员员工很可能仍然可以执行管理员权限。如果被攻击者发现是这种方式执行管理员权限,那么会更加糟糕。

		2.静态文件下载
			如果通过购买收费的电子版书籍,点击下载以后跳转到一个www.example.com/download/0636628104.pfb链接。

			攻击方式:
				攻击者可以通过修改063328104(图书的ISBN编码),那么就可以下载自己任何想要的书籍

	访问控制的防护
		1.不要信任用户提交的表示访问的参数(如admin=true);

		2.假设用户知道每一个URL和标识符,确保应用程序的访问控制足以防止未授权的访问

		3.不要认为用户将按照设定的顺序访问应用程序页面,例如不要认为用户无法访问编辑页面,就不能够编辑用户的内容

		4.不要相信用户不会不会篡改客户传送的数据,在每次传值过程中都需要重新检验。

		5.对于敏感的页面(例如管理员界面),可以通过限制IP地址,确保只有特殊网络才能够访问。

		6.对于静态内容的保护,先向动态页面传送一个文件名,经过相关的验证,然后间接访问静态文件。

		7.开发者书写访问控制逻辑代码,确保访问者一次访问程序页面。


七、代码注入的攻击与防护

	a.SQL注入攻击
		1.SELECT语句
			1.1登录：
				后台代码:
					String username = request.getParameter("username");
					String password = request.getPrarmeter("password");
					SELECT userid FROM user WHERE username = 'username' AND password = 'password';

				攻击方式:
					在用户名的地方输入 1' or 1=1--
					执行代码为SELECT userid FROM user WHERE username = '1' or 1=1

				后台代码:
					String username = request.getParameter("username");
					SELECT userid FROM user WHERE username 'username';

			1.2查询某个用户是否存在
				攻击方式:
					在用户名的地方输入 1' or '1' = '1
					执行代码SELECT userid FROM user WHERE username = '1' or '1' = '1';

		2.INSERT	
			2.1注册
				如果用户表中有一个关于权限的字段,那么就可能出现注册用户拥有最高权限
				例如用户表有的字段为username,password,level(默认为0)
				后台代码:
					String username = request.getParameter("username");
					String password = request.getParameter("password");
					int level = 0;
					INSERT ITNO user(username,password,level) VALUES('username','password',level);

				攻击方式:
					在username的地方输入
						admin','admin',999)'--
					执行代码:
						INSERT ITNO user(username,password,level) VALUES('admin','admin',999)'
				
		3.UPDATE
			3.1执行修改密码操作
				后台代码:
					String username = request.getParameter("username");
					String password = request.getParameter("password");
					String newPassword = request.getParameter("newPassword");
					UPDATE user SET password = 'password' WHERE username = 'username' AND password = 'password';

				攻击方式:
					在新密码的地方输入1' where 1 = 1--
					执行代码UPDATE user SET password = '1' where 1=1;导致所有用户的密码都被修改

		4.DELETE
			3.1删除某个商品
				后台代码:
					String productid = request.getParameter("productid");
					DELETE FROM products WHERE productid = 'productid';

				攻击方式:
					在产品编码的地方输入 1' or 1=1--
					执行代码DELETE FROM products WHERE productid = '1' or 1=1。导致产品表的所有内容都被删除

		SQL注入的防护
			1.参数化查询
				使用参数化查询,我们可以确定查询结构.上面的的简单注入都是可以避免的,因为输入的所有内容,不管包含什么,都只是当做内容处理,不会当做命令去执行。
				后台代码：
					String username = request.getParameter("username");
					String password = request.getParameter("password");
					String sql = "SELECT userid FROM user WHERE username = ? AND password = ? ";
					st = con.prepareStatement(sql);
					st.setString(1,username);
					st.setString(2,passwprd);
					result = se.executeQuery();

			2.访问数据库的时候使用较低的数据库管理员权限，因为大多数数据库操作，只是简单的读操作。这样即使遭到SQL注入，也可以降低损失到最低。

八、跨站点脚本攻击与防护

	a.常见漏洞
		1.将用户输入的内容喧嚷到HTML页面
		攻击方式:
			<script>
				while(true){
					alert(1)
				}
			</script>
			经过测试,上面的代码在最新版本的谷歌不会执行,谷歌浏览器会给出一个警告,但是在微软的edge会执行,如果会执行上面的代码，那么可以在script脚本中书写危害性更加大的内容。
			例如书写获取用户cookie的脚本,然后伪装成用户,身份去执行相关的请求

		2.在输入框输入JavaScript脚本
			姓名:<input type="text" text="" />
			输入内容: "><script>alert(1)</script>// 
			最后HTML页面的内容为<input type="text" text="" value=""><script>alert(1)</script>
			通过注释,也将执行JavaScript代码

	这一块内容太多，太复杂，现在只能够整理一点基础的。