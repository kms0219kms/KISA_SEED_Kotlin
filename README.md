[Kotlin] KISA SEED 암호알고리즘 구현체
==
### KISA 홈페이지 다운로드 페이지 (JAVA, C)
https://seed.kisa.or.kr/kisa/Board/17/detailView.do

### 사용 방법
1. [Releases 탭](https://github.com/kms0219kms/KISA_SEED_Kotlin/releases)에서 사용을 원하는 알고리즘의 kt파일을 다운로드 합니다.
2. 다운로드 받은 kt파일을 프로젝트에 추가합니다.
3. 사용하고자 하는 알고리즘을 import하고, 위 KISA 홈페이지에서 제공하는 예제 코드를 참고하여 사용합니다.

### 주의사항
- KISA에서 제공하는 JAVA 구현체를 Kotlin으로 변환하여 빌드한 구현체입니다.
- CCM/CMAC/GCM 모드는 KISA_SEED_LIB.kt에 의존하므로 해당 파일을 함께 추가해야 합니다.
- CBC/CTR/ECB 모드는 KISA_SEED_LIB.kt에 의존하지 않습니다.
- 본 구현체를 사용함으로써 발생하는 모든 문제에 대해 책임지지 않습니다.
