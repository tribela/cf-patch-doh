# CF patch DOH proxy

CloudFlare의 DNS Over HTTP를 프록싱 하는 동시에 클라우드플레어로 판단되는 IP의 경우 ICN(대한민국) 리전으로 연결되는 IP로 패치해서 응답해 주는 서버입니다.


## 왜 쓰나요?

한국은 모종의 사정에 의해 클라우드플레어 ICN 리전으로 연결이 잘 안 됩니다. 때문에 일본이나 미국 데이터센터로 연결되고 느린 응답속도를 겪어야 합니다.
이 패치를 사용하면 한국 데이터센터로 연결되어 좀 더 빠른 연결이 가능합니다.


## 어떻게 쓰나요?

사용하시는 DOH 지원 앱에 `https://cf-patch-doh.fly.dev/dns-query`를 추가하시면 됩니다.
DOH 앱 추천 목록
- [Nebulo][], [fdroid][Nebulo-fdroid]
- [Intra][]

[Nebulo]: https://play.google.com/store/apps/details?id=com.frostnerd.smokescreen
[Nebulo-fdroid]: https://git.frostnerd.com/PublicAndroidApps/smokescreen
[Intra]: https://play.google.com/store/apps/details?id=app.intra


## 특정 사이트가 들어가지지 않아요

클라우드플레어 내부 서비스 등은 패치하면 안 되는데도 패치가 들어가는 경우 접속이 안 되거나 에러가 뜨는 경우가 있습니다. 안 되는 사이트 주소를 이슈로 제보해 주세요.
이슈 남겨주시면 BYPASS_LIST에 추가해드립니다.


## 프라이버시

cf-patch-doh.fly.dev는 fly.io에서 호스팅 되며, 접속 로그는 남습니다.
일반적으로 DOH 요청은 POST로 요청되어 접속 로그엔 어떤 DNS 요청을 했는지 전혀 남지 않습니다.


## 기타

- 1.1.1.1은 클라우드플레어의 소유물입니다.
- 이 프로그램, 서비스를 사용하면서 발생하는 문제는 책임지지 않습니다.
