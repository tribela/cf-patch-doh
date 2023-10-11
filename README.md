# CF patch DOH proxy

CloudFlare의 DNS Over HTTP를 프록싱 하는 동시에 클라우드플레어로 판단되는 IP의 경우 ICN(대한민국) 리전으로 연결되는 IP로 패치해서 응답해 주는 서버입니다.


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
