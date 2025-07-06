// --- DOM Elements ---
const setTypeSelect = document.getElementById('set-type');
const setNumberSelect = document.getElementById('set-number');
const startButton = document.getElementById('start-button');
const flashcardArea = document.getElementById('flashcard-area');
const meaningText = document.getElementById('meaning-text');
const spellInput = document.getElementById('spell-input');
const submitAnswerButton = document.getElementById('submit-answer-button');
const hintButton = document.getElementById('hint-button');
const showAnswerButton = document.getElementById('show-answer-button');
const feedbackText = document.getElementById('feedback-text');
const pointsSpan = document.getElementById('points');
const streakSpan = document.getElementById('streak');
const totalWordsSpan = document.getElementById('total-words');
const correctWordsSpan = document.getElementById('correct-words');
const incorrectWordsSpan = document.getElementById('incorrect-words');
const progressBar = document.getElementById('progress-bar');
const historyList = document.getElementById('history-list');
const historyArea = document.getElementById('history-area');
const reviewArea = document.getElementById('review-area');
const reviewFlashcardDiv = document.querySelector('.review-flashcard');
const selectionArea = document.querySelector('.selection-area');
const progressArea = document.querySelector('.progress-area');


// --- Global State ---
let allWordsData = {};
let currentWordSet = [];
let currentWordIndex = 0;
let points = 0;
let streak = 0;
let correctCount = 0;
let incorrectCount = 0;
let wordsToReview = [];
let isReviewSession = false;

const VOCA_DATA = `
Let's Voca 전체 단어
Day 01
notify: 통지하다, 알리다
idle: 일이 없는, 놀고 있는; 게으른
autonomy: 자율, 독립성; 자치권
release: 풀어주다; 공개하다, 발표하다, 발매하다
worldwide: 세계적인
despair: 절망, 낙담
bizarre: 별난, 괴상한
peel: 껍질을 벗기다
consume: 써서 없애다, 소모하다
slender: 날씬한, 호리호리한
emerge: 나타나다, 서서히 나오다
submit: 제출하다
legacy: 유산
outbreak: 발발, 발생
reform: 개혁하다, 개정하다, 개선하다
nuclear: 핵의, 핵무기의, 핵무기를 가진
astonish: (대단히) 놀라게 하다
conservative: 보수적인
virtue: 높은 도덕심, 미덕
excel: 뛰어나다, 탁월하다
precise: 정확한, 정밀한
supervise: 감독하다
flaw: 흠, 결함
bond: 유대, 결속
reveal: 드러내다, 폭로하다
Day 02
disorder: 무질서, 혼란; 장애, 질환
tenant: 세입자, 임차인
stimulate: 자극하다, 고무하다
evolve: 진화하다, 발전하다
contradict: ~에 반대되다, 반박하다
absorb: (액체·기체 등을) 빨아들이다, 흡수하다
prompt: 즉각적인, 신속한; 자극하다, 유발하다
mutual: 서로 간의, 공통의
scar: 흉터, 자국, 흠집
obligation: 의무, 책임
interfere: (+ in) (~에) 간섭[참견]하다; (+ with) (~을) 방해하다
flourish: 번창하다, 번성하다
brutal: 잔인한, 무자비한
genuine: 진짜의
arrest: 체포하다
reproduce: 생식하다, 번식하다
convention: 총회, 대회; 관례, 인습
deed: 행위, 행동
foster: 육성하다, 기르다
stake: (내기 등에) 걸려 있는 것, 판돈; 몫, 지분
burglar: 강도, 도둑
pessimistic: 비관적인, 염세적인
belong to: ~에 속하다, ~의 것이다
devote A to B: A를 B에 바치다, 전념하다
stick to: 고수하다, 끝까지 해내다, 약속을 지키다
Day 03
inspect: 면밀하게 살피다, 검사[점검]하다
obvious: 명백한, 분명한
await: 기다리다, 고대하다
regulate: 규제[통제]하다; 조절하다
candidate: 지원자, 후보자
enroll: 등록하다
fund: 기금, 자금
troop: (pl.) 군인, 병사
burst: 터지다, 터뜨리다
compact: 아담한, 작은; 간결한
deliberate: 고의의, 의도적인; 신중한, 미리 계산된
strategy: 전략, 계획
slang: 속어
highlight: 가장 중요한[인상적인] 부분; (표시 등으로) 특별히 강조하다
innate: 타고난, 선천적인
vomit: 토하다
ethic: 도덕적 가치관, (pl.) (개인·집단의) 윤리적 원칙
confident: 자신감 넘치는
wilderness: (사람이 살지 않는) 미개척지, 황야
durable: 내구성 있는, 오래가는
leap: 껑충 뛰다, 갑자기 (어떤 상태에) 달하다
moderate: 알맞은, 적당한
cope: 처리하다, 대처하다
restore: 복구하다, 회복시키다
overwhelm: 압도하다
Day 04
splendid: 멋진, 화려한
poll: 여론 조사
fabulous: 굉장한, 기막히게 멋진
harsh: 거친, 가혹한
undergo: 받다, 경험하다, 겪다
affair: 일, 업무, 행사
neglect: 방치하다, 소홀히 하다; 방치, 소홀
concrete: 명확한, 구체적인
plague: 전염병, 페스트
resolve: 결심하다, 결정하다; 해결하다, 매듭짓다
reliance: (+on) (~에의) 의존, 기댐
frown: 눈살을 찌푸리다, 찡그리다
stink: 악취를 풍기다
inevitable: 필연적인, 불가피한
era: 연대, 시대
constitute: 구성하다, 이루다
accommodate: (사람·물건을 어떤 공간에) 수용하다; (필요를) 들어주다, 맞춰주다
enthusiastic: 열광하는, 비상한 관심을 보이는
refine: 불순물을 걸러내다; 정교하게 발전시키다[다듬다]
grieve: 몹시 슬퍼하다
dwell: 살다, 거주하다
premature: 너무 이른, 시기상조의
thermometer: 온도계
provide A with B: A에게 B를 제공하다
stuff A with B: A의 속을 B로 가득 채워 넣다
Day 05
considerate: 속이 깊은, 배려심 있는
frustrate: 좌절시키다, 실망시키다
microscope: 현미경
courteous: 정중한, 예의 바른, (몸가짐·말투가) 사려 깊은
handkerchief: 손수건
skyscraper: 마천루, 고층 빌딩
senior: (+ to) (~보다) 고참의, 손위인, 선배의; 고참, 선배, 연장자, 상급생
cemetery: 묘지, 공동묘지
acceptable: 받아들일 수 있는, 그럭저럭 괜찮은
anchor: 닻, 버팀목; 뉴스 진행자
barrel: (원통의) 나무통; <원유의 단위> 배럴
whistle: 호각, 호루라기, 휘파람; 휘파람을 불다
careless: 부주의한, 무신경한
consonant: 자음
criminal: 범죄의, 죄를 짓는; 범죄자, 죄인
contract: 계약; 계약하다
headquarters: 본사, 본부, 사령부
origin: 기원, 발생, 유래
mere: 그저 ~일 뿐인, 단지 ~에 불과한
jury: 배심원단, 심사위원단
reference: 언급; 정보원, 참고자료
pressure: 압력; 압박감
sustainable: (자원 등이) 지속 가능한, 유지[이용]할 수 있는
bullet: 총알, 총탄
zip: ~을 지퍼로 잠그다
Day 06
speculate: 추측해보다
betray: 배신하다, 배반하다
transition: 변천, 이행, 변화
patriot: 애국자
isolate: 고립시키다, 격리하다
revenge: 복수, 보복; 복수하다
diplomacy: 외교
sin: 죄, 죄악
confess: 자백[고백]하다, 인정하다
fake: 가짜, 모조품
statistic: 통계, 통계 수치
barren: 불모의, 메마른
wage: 임금, 급료
expire: 끝나다, 만기가 되다
vow: 맹세하다, 서약하다; 맹세, 서약
collapse: 무너지다, 쓰러지다, 폭락하다
inherent: 선천적인, 본래부터 있는, 내재된
relief: (통증의) 진정, 안심, 안도; 구제, 구호품
peninsula: 반도
descend: 내려가다, 하락하다; ~혈통[후손]이다, (대대로) 전해지다
applaud: <자> 박수 치다; <타> 갈채를 보내다, 적극 지지하다
see red: 매우 화가 나다
see eye to eye: (+ with) (~와) 견해가 일치하다
see the point of: ~의 요점을 파악하다
not see the forest for the trees: 나무를 보느라 숲을 못 보다, 작은 것에 연연해 큰 것을 놓치다
Day 07
fort(ress): 요새, 기지
interact: 상호 작용하다; 소통하다
portray: 그리다, 묘사하다
leak: <자> (액체가) 새다; <타> 누설하다
significant: 중요한, 의미 있는
colony: 식민지
exhale: (숨을) 내쉬다
herd: (가축의) 떼, 무리
reserve: 예약하다; (나중에 쓰려고) 남겨두다
reservoir: 저수지, 저장소; 보고
gaze: 뚫어지게 보다, 빤히 보다
fabric: 천, 직물
enhance: 높이다, 향상시키다
modest: 겸손한; 수수한; (크기·양이) 적당한
dreadful: 무서운, 무시무시한; 지독한, 형편없는
primitive: 원시의, 미개한, 원시적인
tempt: 유혹하다, 꼬드기다
deserve: (보상·대가를) 받을 만하다, 자격이 있다
appliance: 기구, 기기
blink: 눈을 깜박거리다
curse: 저주하다, 욕하다; 저주, 악담
benefit: 이익, 좋은 점; <자> 득을 보다; <타> ~에게 도움[혜택]을 주다
publicity: 언론의 관심[주목], 홍보
conference: 협의, 회의
altogether: 아주, 완전히; 모두 합해서
Day 08
notorious: 악명 높은
renowned: 유명한, 명성이 높은
deceit: 사기, 속임수
peculiar: 특이한; (+to) (~만의) 독특한, 특유의
savage: 야만적인, 잔인한, 사나운
acid: 신맛이 나는, 산성의; 산(酸)
cuisine: 요리, 요리법
endure: <타> 참다, 견디다; <자> 지속되다
investigate: 조사하다, 수사하다
foul: 반칙; 못된, 비열한; 역겹도록 싫은
pinch: 꼬집다; 꼬집기; 한 꼬집
wholesale: 도매(상)의, 대량 판매의
differ: 다르다, 의견이 다르다
extraordinary: 비범한, 특출난
budget: 예산
motivate: ~에게 동기를 부여하다, 자극하다
overall: 전부의, 전반적인; 대체로, 전반적으로
commission: (특정 임무를 수행하는) 위원회; 위임, 대행수수료; (~에게 일을) 의뢰하다, 맡기다
splash: <자> (물 등이) 튀기다, 첨벙첨벙 걷다, 첨벙 소리를 내다; <타> (물을) 튀기다
ally: 동맹국, 동맹자; 동맹을 맺다, 연합하다
sow: 씨를 뿌리다, 농작물을 심다
blow up: <자> 폭발하다; <타> 폭발시키다; (풍선 등을) 부풀리다
break up: (+ with) (~와) 헤어지다, 결별하다
catch up with: ~와 같은 수준에 이르다, ~를 따라잡다
stand up: 기다리게 하다, 바람맞히다
Day 09
permanent: 영구적인, 오래가는
reverse: 방향을 거꾸로 하다, 맞바꾸다
slap: 찰싹 때리다
eclipse: 일식, 월식
trivial: 하찮은, 사소한
nominate: 후보로 지명[추천]하다; (공직·영예에) 임명하다
demolish: 완전히 부수다, 결딴내다, 무참히 패배시키다
extract: 뽑아내다, 추출하다
gracious: 배려 깊은, 친절한
logic: 논리, 논리학
upgrade: 개선하다, 등급을 높이다
alert: 경고하다, 경계를 당부하다; 경계 태세
forefather: 조상, 선조
retire: 퇴직하다, 은퇴하다
bait: 미끼
prospect: 전망, 가망, 가능성
fertile: 기름진, 비옥한
celebrity: 유명인사, 연예인
sustain: 지속시키다, 지탱하다; 기본적인 의식주를 제공하다
emit: 내다, 내뿜다, 방출하다
outcome: 결과, 성과
skeptical: 회의적인, 의심 많은
abandon: 버리고 가다, 방치하다; 포기하다, 단념하다
contaminate: 오염시키다
qualify: <타> 자격을 갖추게 하다; <자> 자격요건에 부합하다, 자격[능력]이 되다
Day 10
independent: 독립적인, 독립된
drastic: (조치·수단 등이) 과감한, 과격한
starve: 배고프다; 굶주리다, 굶어 죽다
roast: (불·오븐에) 굽다; 구이, 구이용 고기
fundamental: 근본적인, 핵심의
identical: 똑같은, 매우 닮은
migrate: (서식지를) 이동하다, 이주하다
creative: 독창적인, 창의력 있는
anxiety: 불안, 걱정
bully: 못살게 굴다, 괴롭히다; 친구를 괴롭히는 아이, 불량배
intention: 의도, 의향
simulate: 모방하다, 재연하다; 가장하다, ~인 체하다
coincidence: (우연의) 일치, 동시발생
kneel: 무릎을 꿇다, 굴복하다
critic: 비판하는 사람; 비평가, 평론가
existence: 존재함, 현존
weep: 흐느끼다
plausible: 있을 법한, 가능성이 있는
otherwise: 그렇지 않다면, 다른 상황이라면; 다른 식으로, 달리
abstract: 추상적인
basin: 대야, 넓은 대접; <지형> 강 유역, 분지
ask around: 주변에 물어보고 다니다, 수소문하다
hang around: 어울려[붙어] 다니다, (별 목적 없이 어떤 장소에) 죽치다, 얼쩡대다
shop around: (가게를 돌아다니며) 가격을 비교하다
turn around: 뒤돌아서다, 뒤돌아보다
Day 11
severe: 극심한, 혹독한, 가혹한
diagnose: (질환·문제를) 진단하다
boundary: 경계
patrol: 순찰하다; 순찰, 순찰 경관
insight: 통찰력, 식견
handy: 바로 쓸 수 있는, 손 닿는 곳에 있는; 편리한
victim: 희생자
furnish: 살림살이를 비치하다; 제공하다, 공급하다
rip: <타> 찢다, 째다; <자> 찢어지다
shrink: 줄다, 줄어들다, 감소하다
apparent: 명백한, 분명한
negotiate: 협상하다
prosper: 번영하다, 번창하다
fierce: 사나운, 거친; 심한, 치열한
sprain: (발목, 손목 등을) 삐다; 삠, 염좌
entitle: 자격을[권리를] 주다
dispensable: 없어도 되는
wrinkle: 주름; 주름지게 하다
sting: 찌르다, 쏘다
territory: 영토
chamber: 회의실, 집무실; 방, 침실
glance: 흘끗[슬쩍] 보다; 흘끗 봄
chronicle: 연대기, 역사적 기록; 연대순으로 기록하다
decisive: 결단력 있는, 단호한
unravel: (실 등을) 풀다; 해명하다, 해결하다
Day 12
boom: 급격히 성장[증가]하다; 급증, 급성장
prairie: 대초원, 목초지
ashore: 해안가로, 육지로
status: 지위; 상태
oppose: 반대하다
punctual: 시간[기한]을 잘 지키는
execute: 실행하다, 집행하다
subscribe: (+to) 구독하다, (서비스에) 가입하다
relevant: <+ to> 관련된, 관계 있는
console: 위로하다
immediate: 즉각적인, 즉시의
creep: 살금살금[몰래] 움직이다
pesticide: 살충제
discharge: 배출하다; 내보내다, 풀어주다
asset: 유용한[가치 있는] 것, 재원, 자산
surrender: 넘겨주다, 양도하다; 항복하다, 굴복하다
equality: 동등함, 평등
reinforce: 강화하다, 보강하다
fade: 희미해지다, 약해지다, 사라지다
let ~ know: ~에게 알려주다, 알리다
let alone: ~은 말할 것도 없고, ~은커녕
let go of: ~를 놓아주다, ~에서 손을 떼다
let ~ loose: 자유롭게 풀어 놓다
let ~ slip: 무심코 내뱉다, 말해 버리다
let bygones be bygones: 지나간 일은 따지지 않다, 과거의 일은 잊어버리다
Day 13
scan: 재빨리 훑어보다; 찬찬히 살피다
enormous: 거대한, 어마어마한
occupy: (장소·자리를) 차지하다, 점유하다
income: 소득, 수입
radical: 급진적인, 과격한
crucial: 결정적인, 중대한
self-conscious: 남의 시선을 의식하는, (자신의 외모·행동을) 지나치게 신경 쓰는
antipathy: 반감, 적대감
prevail: <+over> (~보다) 우세하다; 널리 퍼지다, 유행하다
illusion: 환상, 환영, 착각
decent: 점잖은, 품위 있는; 괜찮은, 나쁘지 않은
forbid: 금하다, 허락하지 않다
edible: 먹을 수 있는, 식용의
proclaim: 정식으로 발표하다, 선포하다
sphere: 구, 둥근 물체; (세력) 범위, (활동) 분야
carve: 새기다, 조각하다
grip: 움켜쥠; 단단히 쥐다
browse: 이리저리 훑어보다, 그냥 둘러보다
dispute: 다투다, 논쟁하다; 논쟁, 마찰
therapy: 요법, 치료
sacrifice: 희생하다; 희생
considerable: 상당한, 꽤 많은
manuscript: 원고
committed: 헌신하는, 매진하는
warehouse: 창고, 도매점
Day 14
vacant: 텅빈, 비어 있는
painstaking: 엄청난 공이 드는
stare: 빤히 쳐다보다, 응시하다
pregnant: 임신한
bulk: 대량, 대부분
obtain: 얻다, 손에 넣다
supernatural: 초자연적인, 불가사의한
cease: <자> 그치다; <타> 그만두다, 중지하다
assign: 배정[할당]하다, (과제를) 부여하다
farewell: 안녕, 작별 (인사)
dare: <주로 부정문·의문문에서> 감히 ~하다
enterprise: 기업(체), 회사
snore: 코를 골다
infect: 감염시키다, 전염시키다
numerous: (수적으로) 많은, 무수한
expand: <타> 확장하다; <자> 팽창하다
recreation: 여가활동, 오락, 휴양
bore: 지루하게 하다
distress: 심적인 고통, 불안감; (배의) 조난, 위급한 상황
peak: 산꼭대기, 정상; 절정, 최고치
awaken: <자> (잠에서) 깨다; <타> (잠을) 깨우다; 일깨우다, 자각시키다
corporate: 기업의, 법인의
cut ~ into pieces: ~을 조각조각 자르다
drag ~ into: (억지로) ~를 끌어들이다
translate A into B: A를 B로 번역하다
Day 15
flesh: 살, 살점
tease: 놀리다, 괴롭히다
substitute: <타> ~을 대신 쓰다; <자> 대체하다; 대타, 대용품
exceed: 넘다, 초과하다
certificate: 증명서, 인가증, 자격증
abolish: 폐지하다
haste: 급함, 서두름
accomplish: 해내다, 달성하다
applicant: 지원자, 신청자
profession: (전문적인) 직업, 일
expenditure: 지출, (지출된) 비용
relocate: <타> 이주시키다; <자> 새로운 곳으로 옮기다
ministry: (정부) 행정부처
content: (용기 속의) 내용물, (책의) 내용, 목차; 만족하는, 더 바랄 게 없는
bump: 부딪치다, 충돌하다; 부딪침
outline: 윤곽, 요점; 윤곽을 그리다, 요점을 말하다
detect: 찾아내다, 감지하다
odor: 냄새
orbit: 궤도; 원을 그리며 돌다
knot: 매듭, 묶음; 매듭을 만들다, 묶다
perish: (재해 등으로) 형체가 사라지다, 죽다
utilize: 활용하다, 이용하다
sensation: 감각, 지각; 커다란 반향[선풍]을 일으킨 것
chronic: (병이) 만성인, 고질적인
invoke: (법·권리를) 발동[행사]하다, ~에 호소하다; (신의 은총을) 간절히 청하다
Day 16
pitch: 던지다, 투구하다; 던지기
medieval: 중세의
indict: 기소하다
commodity: 상품
prohibit: 금하다, 금지하다
lease: 임대차 계약, 임차권; (땅·집·물건 등을) 임대하다, 빌려주다; (임대 계약으로) 빌려 쓰다
oral: (글이 아니라) 말로 하는, 구술의
sarcastic: 비꼬는, 빈정대는
recipient: 수령인, 수취인, 수상자
illustrate: 설명[예증]하다; (책에) 삽화를 넣다
resign: 사임하다, 퇴직하다
abuse: 남용하다; 학대[착취]하다; 남용, 악용; 학대, 착취
anonymous: 익명의, 작자 미상의
gene: 유전자
counsel: 조언하다, 상담하다; 조언, 상담
solitary: 혼자의, 고독한
frank: 솔직한, 숨김없는
chum: 친한 친구
distribute: 나누어 주다, 보급하다, 배포하다
clash: 충돌, 격돌; 격돌하다, 충돌하다
eliminate: 제거하다, 없애다
arrive at: ~에 도착하다, 목표 지점에 이르다
get at: 손에 닿다, 미치다
laugh at: ~를 놀리다, 비웃다
smile at: ~에게 미소 짓다
Day 17
wipe: (깨끗이) 닦다, 닦아서 없애다
rehearse: 연습하다, 예행 연습하다
smash: 산산조각 나다; 세게 부딪치다
input: 의견, 조언, 도움; (컴퓨터에 입력되는) 정보; 입력하다
shortage: 부족, 결핍
appoint: 선발하다, 임명하다; (시간 등을) 정하다
corrupt: 부패한, 변질된; 타락시키다, 변질시키다
justice: 정의
vital: 매우 중요한, (생명에) 꼭 필요한
overdue: 연체된, 기한이 지난
superb: 최고의, 우수한
facilitate: 용이하게 하다, 덜 불편하게 하다
sober: 취하지 않은, 정신이 말짱한
compensate: <타> (손실·피해에 대해) 보상하다; <자> (+for) (~을) 보상해주다, (~에 대한) 위로가 되다
potential: 잠재적인, 가능성 있는; 가능성, 잠재성
elaborate: 공들인, 정교한
distort: 비틀다; (사실을) 왜곡하다
multiple: 다수의, 여러 다양한
reside: 살다, 거주하다
session: (국회의) 회기, 개회, (법정의) 개정; 단체활동 시간[기간]
evaluate: (재산·능력을) 평가하다, 측정하다
sniff: 냄새를 킁킁 맡다
breathe: 호흡하다, 숨을 쉬다
tolerate: 참다, 너그럽게 봐주다
assertive: 자기 주장을 강하게 펴는
Day 18
abortion: 낙태
command: (~하도록) 명령하다; (군대 등을) 지휘하다
revive: <자> 되살아나다; <타> 부활시키다
dedicate: 바치다, 헌신하다
hazard: 위험, 해악
treaty: 조약, 협정
gain: 얻다, 늘리다; 이익, 이득; 증가
perspective: 견해, 관점
sponsor: 후원하다; 후원자
phase: 단계, 국면
barrier: 장애물, 걸림돌
inject: 주사하다, 주입하다
navigate: 항해하다, 돌아다니다
loan: 대여, 대출, 융자; 빌려주다
coordinate: (여러 다양한 활동을 하나로) 조직하다, 조정하다
fatal: 치명적인; 중대한, 심각한
digest: 소화하다; 잘 이해하다, 터득하다; 요약본, 개요
excess: 과잉, 초과, 지나침
auction: 경매
beloved: 깊이 사랑하는
come clean: 자백하다, 진실을 털어놓다
look on the bright side: 긍정적인 면을 바라보다, 긍정적으로 생각하다
look good on: ~에게 잘 어울리다
look young for one's age: 나이보다 젊어 보이다
look ~ in the face[eye]: ~를 똑바로 쳐다보다, 정면으로 바라보다
Day 19
flexible: 탄력적인, 유연한
trace: 자취, 흔적; 자취를 추적하다
gamble: 내기하다, 도박하다; 노름, 도박
analyze: 분석하다
enforce: 시행하다, 집행하다
defect: 흠, 결함
valid: 유효한; 타당한
cosmos: 우주
sanitary: 위생의, 위생적인, 청결한
instinct: 본능, 직감
mute: 무언의, 묵음의, 벙어리의
estate: 전 재산, (대저택이 있는) 부지
construction: 건설, 건축물
nevertheless: 그럼에도 불구하고
wreck: 난파, 파선; (pl.) 잔해; (배를) 난파시키다, 망가뜨리다
supplement: 보충제, 보조식품
climax: 절정, 최고조
faint: 희미한, 어렴풋한, 엷은; (일시적으로) 실신[기절]하다
internal: 내부의, 안의
dismiss: 해고하다; 해산시키다
approximate: 대략의, 대강의
resent: ~에 대해 분개하다
restrict: 제한하다, 규제하다
provoke: 자극하다, 불러일으키다, 유발하다
output: 생산고, 산출량
Day 20
sweep: 청소하다; 휩쓸다
arrow: 화살, 화살표
submerge: <타> 물속에 잠기게 하다; <자> 잠수하다, 물속에 들어가다
accountable: <+ for> (~에 대해) 책임이 있는
context: 문맥, 전후의 상황, 맥락
biography: 전기, 일대기
competitive: 경쟁의, 경쟁심이 강한, 경쟁력 있는
lid: 뚜껑
communication: 의사소통, (pl.) 통신
bundle: 한 묶음, 뭉치, 꾸러미
device: 기계장치, 기기
fetch: (가서) 가지고 오다, 가져다 주다
impose: (세금·규율 등을) 부과하다, 강요하다
characteristic: (pl.) (두드러진) 특성, 특징; 전형적인, 특징적인
pale: (안색이) 창백한; (색이) 옅은
profile: (사람에 대한 중요 사실을 요약한) 프로필, 인물소개
vast: (크기·면적이) 방대한, 드넓은; (수·양이) 막대한
motive: 동기, 이유
specify: 명시하다, 구체적으로 말하다
remark: 발언, 한 마디; 말 한 마디 하다
ambitious: 야망이 있는, 성공하고자 하는
cross out: (줄을 그어) 지우다
figure out: 이해하다, (문제 등을) 알아내다
put out: 불을 끄다
run out: <+ of> (~이) 다 떨어지다, 다 써버리다
Day 21
component: 성분, 구성 요소
breed: (번식을 위해) 사육하다; 품종
nutrient: 영양소
compromise: 타협; 타협하다
respective: 저마다의, 각각의
nurture: (성장하도록) 보살피다, 기르다; 영양분을 공급하다
detach: 떼다, 분리하다
humanity: 인류; 인간성, 인류애
fulfill: 다하다, 이행하다; 채우다, 만족시키다
associate: 관련 짓다, 연상하다; 동료, 동업자
portion: 부분, 일부
expel: 내쫓다, 추방하다
keen: 날카로운, 예리한; 열렬한, 열망하는
misuse: 남용, 악용, 오용; 남용하다, 악용하다, 오용하다
gender: 성, 성별
irritate: 짜증나게 하다, 신경을 거슬리게 하다
blast: (바람·공기의) 강한 몰아침[불어 닥침]; 폭발
frontier: 국경; 미개척 분야, 첨단 분야
refuge: 피난처, 은신처
enlarge: 확대[확장]하다, 넓히다
dim: 어두침침한; 흐릿한, 어렴풋한
cooperate: 협력하다, 협동하다
stun: 깜짝 놀라게 하다, 기절시키다
flatter: 아첨하다, 아부하다
comprehensive: 포괄적인, 종합적인, 광범위한
Day 22
crack: 갈라진 틈, 금
bias: 편견
liberal: 자유주의의, 진보적인
slam: (문 등을) 쾅 닫다
phenomenon: 현상, 사건
apparel: 옷, 의류
weave: (천·직물 실을) 짜다
courtesy: 예의 바름, 공손
outdated: 구식의, 시대에 뒤진
soothe: 달래다, 진정시키다, 가라앉히다
epic: 서사시의, (스케일이) 장대한; 서사시
diagram: 도표, 도형, 그림
acquire: 얻다, 취득하다
invade: 침략[공격]하다; (권리 등을) 침해하다
definite: 확실한, 명확한
correspond: 일치하다; 해당하다
shame: 수치, 창피스러움; 실망스러운 일
presume: 추정하다, ~라고 생각하다[여기다]
pirate: 해적; 해적질하다; 무단복제하다
nuisance: 불쾌하게[짜증나게] 하는 것, 골칫거리
resist: 저항[반대]하다; 견디다, 참다
carriage: 탈것, 마차; (철도의) 객차
cut corners: 지름길로 가다, (돈·시간 등을) 절약하다
cut out for: (직업에) 적합한, 적성인
to cut a long story short: (할 얘기는 많지만) 짧게 말하면
Day 23
urgent: 다급한, 긴박한
exaggerate: 과장하다, 부풀리다
stock: 재고(품)
assist: 옆에서 돕다, 거들다
naked: 나체의, 벌거벗은; 육안의
grease: 기름, 윤활유
vertical: 수직의, 세로의
invest: 투자하다
feminine: 여자의, 여성스러운
bachelor: 독신 남자
consist: 이루어져 있다, 구성되다
overtake: 따라잡다, 추월하다
habitual: 평소 습관화된, 상습적인
sew: 바느질하다, 꿰매다
appearance: 출현; 외모, 겉모습
tap: 가볍게 두드리다; (수도의) 꼭지, (통의) 마개
momentary: 순식간의, 순간적인
gossip: 뜬소문, 잡담
sparkle: 빛나다, 반짝이다
disable: 불구로 만들다; 작동을 멈추다, 무력화하다
customize: 주문 제작하다, 사용자에게 맞춰 만들다
eternal: 영원한, 끝없는
controversy: 논쟁, 논란
regardless: 상관하지 않는, 개의치 않는
ruthless: 무자비한, 몰인정한
Day 24
install: 설치하다, 장착하다
ensure: 확실히 ~하도록 하다, 보장하다
witness: 목격하다; 목격자, 증인
plot: 줄거리; 음모, 계획
conduct: 시행하다, 실시하다; 행위, 행동
diameter: 지름
bureau: (관청의) 국(局), 부(部)
anticipate: 예상하다, 기대하다
retail: 소매; 소매의
countless: 셀 수 없이 많은, 무수한
ray: 광선, 한 줄기 빛
illuminate: 등불을 켜다, 환하게 밝히다; 명확히 보여주다
satire: 풍자
adore: 사랑하다, 너무 좋아하다
disgrace: 불명예, 망신
imprison: 감옥에 가두다, (형기를) 복역하게 하다
exclude: 못 들어오게 하다, 배제[제외]시키다
persist: 지속하다, 계속~하다; <+ in> 고집하다
susceptible: (외부의 영향·해에) 취약한
tremendous: 엄청난, 거대한, 굉장한
diminish: 감소하다, 줄어들다
cultivate: 경작[재배]하다; 계발하다
die of: ~으로 죽다
dispose of: ~을 없애다, 제거하다, 처분하다
rob A of B: A에게서 B를 빼앗다[훔치다]
Day 25
embarrassing: 창피스럽게 하는, 당혹스러운, 민망한
initiative: 주도적으로 나섬, 솔선수범
telescope: 망원경
multiply: <자> 늘다, 가중되다; <타> 늘리다, 증가시키다
yearn: 간절히 바라다, 동경하다
frugal: 검소한, 절약하는, 소박한
epidemic: 유행병, 전염병; 유행성의, 만연하는
formula: <수학> 공식; 조제법
coherent: (논리가) 일관성 있는
accuse: 잘못이 있다고 비난하다; 고소[고발]하다
veil: (면사포처럼) 얇은 천, (보이지 않게) 가리는 것; 가리다, 덮다
assembly: 국회, 입법부; (정기) 회합, 총회
pronounce: 널리 알리다, 공표[선언]하다; 발음하다
blade: 칼날, 스케이트 날
panel: (특정 목적으로 모인) 전문 위원단, 패널
indispensable: 불가결한, 꼭 필요한
smother: <타> 숨막히게 하다, 질식시키다; <자> 숨막히다
resident: 주민, 거주자
stem: (초목의) 줄기, 대공; <원인> 생기다, 유래하다
calculate: 계산하다; 예측하다
continent: (세계 7대륙 중 하나인) 대륙
limb: (나무의) 큰 가지; 팔다리
charming: 매력적인, 기분을 좋게 하는
address: <+to> (~ 앞으로) 우편물을 보내다, (우편물에) 주소를 쓰다; ~에게 말[연설]하다
paw: (네 다리와 발톱이 있는 동물의) 발
Day 26
immature: 미숙한, 철이 덜 든
organized: 체계적인, 준비성이 철저한, 정리정돈을 잘하는
straw: 지푸라기, 빨대
attitude: 자세, 마음가짐, 견해
bloom: 꽃, 꽃을 피우다
capacity: 수용 능력, 용량
adolescent: 미성년자, 십대, 청소년의
complaint: 불평, 불만
nerve: 신경 섬유[조직], 용기, 배짱
vessel: (액체) 저장 탱크, 큰 선박, 배
crunch: <타> 오도독 씹다[부수다] <자> (바스락) 부서지다, (깨물거나 밟아서) 오도독[바삭바삭] 하는 소리
government: 정부, 국가 운영, 국무
infrastructure: (수도·전기·도로 등의) 기반시설, 인프라
journal: 일기, 일지, 학술지, 정기간행물
publication: 출판(물), 발행
continuous: 계속되는, 중단 없는
tune: 선율, 멜로디, 하모니, 화음
rod: (가느다란) 막대기, 회초리, 매
displace: (살아온) 터전에서 내쫓다, ~의 자리를 차지하다
literal: 글자 그대로의, 사실에 충실한, 문자의
workout: 체력 단련, 운동
tell someone's fortune: ~의 미래를 점치다, 운세를 보다
Tell me about it.: <상대방의 말에 동의할 때> 내 말이 (바로 그거야), 그러게 말이야
time will tell: 시간이 지나면 자연히 알게 된다
tell the difference: <+ between> (~의) 차이를 알다, 구분하다
Day 27
easy-going: 느긋한, 여유로운
stale: 신선하지 않은, 냄새 나는, 김이 빠진
duration: (시간의) 지속, 지속 기간
hard-working: 성실한, 노력파인
expedition: 원정, 탐험대
hostile: 적의의, 적대하는
tin: <화학> 주석
visual: 시각적인, 시력의
attraction: 흥미로운 점, 매력, 관광명소
majority: 다수, 과반수
quarrel: 말다툼, 언쟁; 다투다, 언쟁하다
jail: 구치소, 감옥; <주로 수동태> 감옥에 가두다
substantial: 실체가 있는, 실질적인; (크기·양·무게가) 상당한
greed: 탐욕, 욕심
blossom: 꽃망울; 꽃이 피다, 꽃을 피우다
inhibit: 막다, 억제하다; 금지하다
contrary: 정반대인, 상충하는; 완전히 다른 것
distinct: 확연히 다른, 뚜렷이 구분되는
utter: 철저한, 완전한
Day 28
alongside: ~의 바로 옆에서, ~과 함께
grateful: 감사하는, 고마움을 느끼는
bankruptcy: 재산을 모두 잃고 망함, 파산
mass: (형태가 일정하지 않은) 덩어리; 많은 [양]
voluntary: 자발적인, 자의에 의한; (대가 없는) 자원봉사의
cite: (근거·증거로) 언급하다, 인용하다
initial: 처음의
physics: 물리학
scenario: 시나리오, 각본, 가상의 사건 전개
convene: <타> (회의를) 소집하다; <자> 모이다
introverted: 내성적인
division: 분열, 분리; (관청·기업의) 부서
extroverted: 외향적인
engineering: 공학기술, 엔지니어링
overweight: 과체중의, 중량 초과의
racial: 인종의, 종족의
chip: 얇고, 잘게 썬 조각, 부스러기; (그릇 등의) 이가 빠진 자국, 흠
common sense: 상식, (경험에서 오는) 삶의 지혜
bounce: <자> 튀어 오르다; <타> 튕기다, 위아래로 들썩거리다
congress: (여러 단체의 대표들이 모이는) 회의, 의회
tendency: 경향, 추세
come across: 우연히 발견하다[만나다]
cut across: 지름길로 가다, 가로질러 가다
get across: (생각·의견을) 이해시키다, 제대로 전달하다
run across: 우연히 발견하다[마주치다]
Day 29
remedy: 치료법, 처방, 대책
squeeze: 압착하다, 짜내다
gratitude: 감사, 고마움
sensitive: 세심한; 예민한
conscience: 양심, 도덕심
upcoming: 다가오는, 곧 있을
avenue: (도시의) 대로, <도로명> ~가
stagger: 비틀거리다, 휘청거리다
attorney: 변호사, 법정 대리인
thrifty: 절약하는, 검소한, 알뜰한
grudge: (오랫동안 품어온) 악감정, 앙심
innovation: 혁신, 쇄신
moody: 변덕스러운, 감정 기복이 있는
convenient: 편리한
dual: 두 가지가 있는, 이중의
boost: 기운을 북돋우다, 상승시키다; 기운[힘]이 나게 함, 활력소
intellectual: 지적인, 지능의; 아주 명석한; 지성인, 인텔리
massive: 거대한, 막대한
weep: 울다, 눈물을 흘리다
offend: 기분 나쁘게 하다, 불쾌하게 하다
debut: (무대·영화에의) 첫 출연, 첫 출연하다, 데뷔하다
diversity: 다양성
screen: (컴퓨터·TV·스마트폰의) 화면; 차단막, 가리개
thorn: 가시, 골칫거리
sprinkle: (가루·부스러기를) 흩뿌리다; (액체·분말의) 뿌리기
Day 30
optimistic: 낙천적인, 긍정적인
platform: 플랫폼, 승강장; 연단
analogy: 유사성, (유사성에 근거한) 비유, 빗댐
fairly: 꽤, 상당히; 공평하게, 정정당당하게
bride: 신부
stubborn: 완고한, 고집불통인
identification: 신원 확인, (신원 확인을 위한) 신분증
consequence: 결과, 영향; 중요성
awesome: 아주 근사한, 멋진
enclose: 둘러싸다; 감싸다; (편지 등에) 동봉하다
mechanism: 기계 장치; 작동 원리, 메커니즘
suite: (호텔의) 특실, 스위트룸
irony: 모순, 반어법
ongoing: 계속되는, 진행중인
cattle: <집합적> 소떼, 소의 무리
receipt: 영수증
screw: 나사; 나사로 죄다, 돌려서 고정하다
tidy: 단정한, 깔끔하게 정돈된; (+ up/away) 치우다, 정돈하다
yield: (결과물로) 생산해내다; 항복하다, 순순히 넘겨주다; 생산물, 수확량
stand trial: 재판을 받다
stand a chance of: ~할 가능성이 있다
stand in one's way: ~를 방해하다, 가로막다
stand firm: 단호한 태도를 보이다, 강하게 대처하다
can't stand: ~을 싫어하다, 참을 수 없다
stand still: 제자리에 있다, 아무 변화가[발전이] 없다

잉코북 전체 단어
Unit 09
alert: 경고하다
break out: 발생하다
bruise: 멍
cosmetics: 화장품
credits: 크레디트
deadline: 기한, 마감 시간
director: 영화감독
drizzle: 비가 보슬보슬 내리다
edit: 편집하다
fake: 가짜의
fright: 공포, 두려움
incredible: 믿을 수 없을 정도로 대단한
industry: 산업
master: 장인, 대가
paste: 붙이다
scene: 장면
shoot: 촬영하다
special effect: 특수 효과
submit: 제출하다
tool: 도구
quality: 질
blame: ~을 탓하다
narrator: 서술자
reviewer: 논평가, 비평가
awesome: 엄청난, 굉장한
Unit 10
abroad: 해외로
accommodation: 숙박 시설
appreciate: 감사하다
available: 이용 가능한
background: 배경
basic: 기본적인, 기초적인
book: 예약하다
entrance: 입구, 출입문
flight: 비행
grab: 급히 먹다, 붙잡다
hostel: 호스텔
in person: 직접
line up: 줄을 서다
local: 지역의
palace: 궁전
phrase: 어구
public: 공공의
referee: 심판
sightseeing: 관광
specific: 구체적인, 정한
head: ~를 향하다
purpose: 목적
museum: 박물관
reduced: 줄인, 축소한
research: 연구, 조사
Unit 11
accessible: 접근 가능한
automatic: 자동의
disabled (the disabled): 장애인들, 장애가 있는
disappear: 사라지다
distinct: 구별되는
fabric: 섬유, 천
fancy: 화려한
individuality: 개성, 특성
load: (무거운) 짐
moustache: 콧수염
practical: 실용적인
sequin: 스팽글
sill: (문)턱, (문)틀
slope: 경사면, 비탈
socket: 콘센트
stroller: 유모차
trend: 경향, 유행
universal: 일반적인, 보편적인
unplug: 플러그를 뽑다
upcycle: 업사이클하다, 더 나은 것으로 만들다
inspire: 고무하다, 영감을 주다
weird: 기이한, 기괴한
concept: 개념
upward: 위쪽을 향한
exhibition: 전시(회)
Unit 12
challenge: 도전하다
cheat: 부정행위를 하다
consequence: 결과
diagram: 도표
force: 강요하다
frustrated: 좌절한
gap: 틈, 공백
illegal: 불법인
manage: (간신히) 해내다, 처리하다
motivate: 동기를 부여하다
organize: 정리하다, 준비(조직)하다
routine: 일상
seal: 봉인하다
snitch: 고자질쟁이
spare: 여분의
stick to: 계속하다, 지속하다
strict: 엄격한
switch off: 끄다
timeline: 연대표
unfair: 불공평한
memorize: 암기하다
absent: 결석한
knowledge: 지식
buddy: 친구
period: 기간, 시기
Reflect 3 Unit 5 Reading 2
allow: 허락하다, 용납하다
deeply: 깊게, 깊이
host: 주인, 주최 측
involve: 포함하다, 관련시키다
popularity: 인기
citizen: 시민, 주민
expose: 들어내다, 노출시키다
interact: 소통하다, 교류하다
organize: 준비하다, 정리하다
relax: 안심하다, 휴식을 취하다
include: 포함하다, 포함시키다
experiential: 경험상의, 경험에 의한
immerse: 몰두하다
stay in touch: 연락하고 지내다
meditate: 명상하다
Reflect 3 Unit 6 Reading 1
actual: 사실상의, 실제의
extremely: 극도로, 극히
participant: 참가자
process: 처리하다
separate: 분리하다
signal: 신호, 표시
stage: 단계
theory: 이론
therapy: 치료법
upsetting: 속상하게 하는
random: 무작위의
emotionally: 감정적으로
scan: 유심히 살피다
decrease: 감소하다, 줄이다
overnight: 밤사이에
Reflect 3 Unit 6 Reading 2
accurate: 정확한
base on: ~를 기반으로
face: 직면하다
identify: 확인하다, 알아보다
record: 기록하다, 녹화하다
alternatively: 그 대신에, 다른 방법으로
benefit: 유익하다, 득을 보다
frequently: 자주
image: 이미지, 인상
unique: 유일한, 특별한
include: 포함하다, 포함시키다
pattern: 모양, 형태
pronounce: 발음하다
entertain: 접대하다, 즐겁게 해주다
confuse: 혼란시키다
Reflect 3 Unit 7 Reading 1
aim: 목표하다
complain: 불평하다, 항의하다
employee: 종업원
hire: 고용하다
think of: ~에 대해 생각하다
analyze: 분석하다
data: 자료, 정보
experiment: 실험하다
solve: 해결하다, 풀다
value: 평가하다
creativity: 창의력
factor: 요소, 인자
unreliable: 신뢰할 수 없는
discuss: 상의하다, 논의하다
analyst: 분석가
Reflect 3 Unit 7 Reading 2
actively: 적극적으로, 활동적으로
effective: 효과적인, 실질적인
otherwise: 그렇지 않으면
require: 요구하다
trouble: 문제, 골칫거리
conscious: 의식하는, 자각하는
increase: 증가하다
product: 상품, 생산품
separate: 분리된, 따로 떨어진
work on: ~에 노력을 들이다
think outside the box: 창의적으로 생각하다
fixed: 고정된, 계획된
professional: 전문적인
doodle: 끼적거리다
colleague: 동료
Reflect 3 Unit 8 Reading 1
access: 접근하다, 다가가다
development: 발달, 성장
intelligent: 지능
obvious: 분명한, 확실한
physical: 신체의
acquire: 획득하다, 얻다
former: 이전의
invent: 발명하다, 지어내다
performance: 실적, 공연
preferable: 선호하는
administrator: 관리자, 행정인
variety: 여러 가지, 다양성
harmful: 해로운, 유해한
additional: 추가의, 보충의
self-determination: 자기 결정 능력
Reflect 3 Unit 8 Reading 2
argue: 말싸움하다, 언쟁하다
convenient: 편리한
look up: 찾아보다
nearby: 근처의, 인근의
strategy: 전략, 계획
combination: 조합, 결합
distracting: 방해하는
material: 재료, 물질
relevant: 관련 있는, 적절한
tend to: ~하는 경향이 있다
effective: 효과적인, 실질적인
laptop: 휴대용 컴퓨터
highlight: 강조하다, 표시를 하다
track: 추적하다, 추격하다
skim: 훑어보다, 스치듯 지나가다
`;

// --- Functions ---

/**
 * Parses the raw vocabulary data into a structured object.
 * The data is expected to be in the format:
 * Book Title
 * Category (e.g., Day XX or Unit XX)
 * word: meaning
 * word: meaning
 * ...
 * Category (e.g., Day YY or Unit YY)
 * word: meaning
 * ...
 */
function parseVocaData(data) {
    const lines = data.trim().split('\n');
    let currentBook = '';
    let currentCategory = '';
    const parsedData = { day: {}, unit: {}, reflect: {} };

    lines.forEach(line => {
        line = line.trim();
        if (!line) return;

        if (line.toLowerCase().startsWith("let's voca 전체 단어")) {
            currentBook = 'voca';
        } else if (line.toLowerCase().startsWith("잉코북 전체 단어")) {
            currentBook = 'inko';
        } else if (line.toLowerCase().startsWith("reflect 3")) {
            currentBook = 'reflect';
            // Expecting format like "Reflect 3 Unit X Reading Y"
            const reflectMatch = line.match(/Reflect 3 (Unit \d+) Reading (\d+)/);
            if (reflectMatch) {
                currentCategory = `${reflectMatch[1]}-R${reflectMatch[2]}`; // e.g., Unit 5-R2
                if (!parsedData.reflect[currentCategory]) {
                    parsedData.reflect[currentCategory] = [];
                }
            } else {
                // If the line starts with "Reflect 3" but doesn't match the expected format,
                // log an error or handle it, but don't use the raw line as a category.
                console.warn("Skipping malformed Reflect 3 line:", line);
                currentCategory = ''; // Reset or skip
            }
        } else if (line.startsWith('Day ') || (line.startsWith('Unit ') && !line.includes("-R"))) {
            currentCategory = line;
            if (currentCategory) { // Ensure currentCategory is not empty from a previous malformed line
                if (currentBook === 'voca' && line.startsWith('Day ')) {
                if (!parsedData.day[currentCategory]) {
                    parsedData.day[currentCategory] = [];
                }
            } else if (currentBook === 'inko' && line.startsWith('Unit ')) {
                 if (!parsedData.unit[currentCategory]) {
                    parsedData.unit[currentCategory] = [];
                }
            }
        } else {
            const parts = line.split(':');
            if (parts.length >= 2) {
                const word = parts[0].trim();
                const meaning = parts.slice(1).join(':').trim();
                if (currentCategory) { // Only add if currentCategory is valid
                    if (currentBook === 'voca' && currentCategory.startsWith('Day ')) {
                        if (parsedData.day[currentCategory]) {
                            parsedData.day[currentCategory].push({ word, meaning });
                        }
                    } else if (currentBook === 'inko' && currentCategory.startsWith('Unit ')) {
                         if (parsedData.unit[currentCategory]) {
                            parsedData.unit[currentCategory].push({ word, meaning });
                        }
                    } else if (currentBook === 'reflect' && currentCategory.includes("-R")) {
                        // Ensure currentCategory is a key that was initialized for reflect
                        if (parsedData.reflect[currentCategory]) {
                             parsedData.reflect[currentCategory].push({ word, meaning });
                        } else if (currentCategory) { // If currentCategory was set by reflectMatch but array not init'd (should not happen with current logic)
                            // This case should ideally not be reached if reflectMatch logic is correct
                            // console.warn("Reflect category", currentCategory, "not initialized for word:", word);
                        }
                    }
                } else {
                    // console.warn("Skipping word due to no valid currentCategory:", line);
                }
            }
        }
    });
    // console.log("Parsed Data:", JSON.stringify(allWordsData, null, 2)); // DEBUG Parsed Data
    return parsedData;
}


/**
 * Populates the set number dropdown based on the selected set type.
 */
function populateSetNumbers() {
    const selectedType = setTypeSelect.value;
    console.log("populateSetNumbers called. Selected type:", selectedType); // DEBUG
    setNumberSelect.innerHTML = '';
    let categories = [];

    if (selectedType === 'day' && allWordsData.day) {
        console.log("Populating for Day. Keys:", Object.keys(allWordsData.day)); // DEBUG
        categories = Object.keys(allWordsData.day).sort((a, b) => parseInt(a.replace('Day ', '')) - parseInt(b.replace('Day ', '')));
    } else if (selectedType === 'unit') {
        console.log("Populating for Unit."); // DEBUG
        const inkoUnits = (allWordsData.unit && Object.keys(allWordsData.unit).length > 0)
                         ? Object.keys(allWordsData.unit).sort((a, b) => parseInt(a.replace('Unit ', '')) - parseInt(b.replace('Unit ', '')))
                         : [];
        console.log("Inko Units:", inkoUnits); // DEBUG

        const reflectKeys = (allWordsData.reflect && Object.keys(allWordsData.reflect).length > 0)
                          ? Object.keys(allWordsData.reflect).sort((a, b) => {
                                const [aUnitPart, aReadingPart] = a.split('-R');
                                const [bUnitPart, bReadingPart] = b.split('-R');
                                const aUnit = parseInt(aUnitPart.replace('Unit ', ''));
                                const bUnit = parseInt(bUnitPart.replace('Unit ', ''));
                                const aReading = parseInt(aReadingPart || "0");
                                const bReading = parseInt(bReadingPart || "0");
                                if (aUnit === bUnit) return aReading - bReading;
                                return aUnit - bUnit;
                            })
                          : [];
        console.log("Reflect Keys (raw from allWordsData.reflect):", reflectKeys); // DEBUG

        categories = [...inkoUnits, ...reflectKeys.map(key => `Reflect ${key}`)];
    }

    console.log("Final categories for dropdown:", categories); // DEBUG

    if (categories.length > 0) {
        categories.forEach(categoryName => {
            const option = document.createElement('option');
            option.value = categoryName;
            option.textContent = categoryName;
            setNumberSelect.appendChild(option);
        });
    } else {
        const option = document.createElement('option');
        option.textContent = "선택 가능한 세트 없음";
        option.disabled = true;
        setNumberSelect.appendChild(option);
        console.log("No categories found, displaying '선택 가능한 세트 없음'"); // DEBUG
    }
}


/**
 * Initializes the application.
 */
function initializeApp() {
    allWordsData = parseVocaData(VOCA_DATA);
    populateSetNumbers(); // Initial population for "Day"

    // Event Listeners
    setTypeSelect.addEventListener('change', populateSetNumbers);
    startButton.addEventListener('click', startGame);
    submitAnswerButton.addEventListener('click', checkAnswer);
    hintButton.addEventListener('click', showHint);
    showAnswerButton.addEventListener('click', showAnswer);
    spellInput.addEventListener('keypress', function(event) {
        if (event.key === 'Enter') {
            checkAnswer();
        }
    });
}


/**
 * Starts the learning game with the selected word set.
 */
function startGame() {
    const selectedType = setTypeSelect.value;
    const selectedNumber = setNumberSelect.value;
    // console.log("startGame triggered with type:", selectedType, "number:", selectedNumber); // DEBUG

    if (!selectedNumber || selectedNumber === "선택 가능한 세트 없음") {
        alert("학습할 세트를 선택해주세요!");
        return;
    }

    currentWordSet = []; // Reset currentWordSet

    if (selectedType === 'day') {
        if (allWordsData.day && allWordsData.day[selectedNumber]) {
            currentWordSet = [...allWordsData.day[selectedNumber]];
        }
    } else if (selectedType === 'unit') {
        if (selectedNumber.startsWith('Reflect')) {
            const reflectKey = selectedNumber.replace('Reflect ', ''); // This should give "Unit X-RY"
            // console.log("Looking for Reflect key:", reflectKey); // DEBUG
            if (allWordsData.reflect && allWordsData.reflect[reflectKey]) {
                currentWordSet = [...allWordsData.reflect[reflectKey]];
            }
        } else { // Standard Inko Unit
            if (allWordsData.unit && allWordsData.unit[selectedNumber]) {
                currentWordSet = [...allWordsData.unit[selectedNumber]];
            }
        }
    }

    // console.log("currentWordSet after selection:", currentWordSet); // DEBUG

    if (!currentWordSet || currentWordSet.length === 0) {
        alert("선택한 세트에 단어가 없거나, 단어 목록을 불러오는 데 실패했습니다. 개발자 콘솔을 확인해주세요.");
        console.error("Failed to load word set. Type:", selectedType, "Number/Key:", selectedNumber, "Parsed Data for reflect:", allWordsData.reflect);
        return;
    }

    // Shuffle the word set for variety
    currentWordSet.sort(() => Math.random() - 0.5);

    currentWordIndex = 0;
    points = 0;
    streak = 0;
    correctCount = 0;
    incorrectCount = 0;
    wordsToReview = [];
    isReviewSession = false;

    updateStatsDisplay();
    clearHistory();
    historyArea.style.display = 'none';


    selectionArea.style.display = 'none';
    flashcardArea.style.display = 'block';
    progressArea.style.display = 'block';
    reviewArea.style.display = 'none';

    totalWordsSpan.textContent = currentWordSet.length; // For initial set
    currentReviewRoundTotal = 0; // Reset for review tracking
    displayNextWord();
}

// --- Global State (add this with other global states) ---
let currentReviewRoundTotal = 0; // Tracks total words for the current review round


/**
 * Displays the next word in the flashcard.
 */
function displayNextWord() {
    spellInput.disabled = false;
    submitAnswerButton.disabled = false;
    hintButton.disabled = false;
    showAnswerButton.disabled = false;

    if (isReviewSession) {
        if (currentWordIndex < wordsToReview.length) {
            const wordData = wordsToReview[currentWordIndex];
            // For review, we might need a different display logic if the structure of reviewFlashcardDiv is different
            // Assuming review also uses meaningText and spellInput for now
            meaningText.textContent = wordData.meaning;
            spellInput.value = '';
            feedbackText.textContent = '';
            spellInput.focus();
        } else {
            endReviewSession();
        }
    } else {
        if (currentWordIndex < currentWordSet.length) {
            const wordData = currentWordSet[currentWordIndex];
            meaningText.textContent = wordData.meaning;
            spellInput.value = '';
            feedbackText.textContent = '';
            spellInput.focus();
        } else {
            // End of the current set
            if (wordsToReview.length > 0) {
                startReviewSession();
            } else {
                endGame();
            }
        }
    }
    updateProgress();
}


/**
 * Checks the user's answer.
 */
function checkAnswer() {
    const userAnswer = spellInput.value.trim().toLowerCase();
    const currentWordData = isReviewSession ? wordsToReview[currentWordIndex] : currentWordSet[currentWordIndex];
    const correctAnswer = currentWordData.word.toLowerCase();

    let isCorrect = false;
    // Allow for answers with '/' by checking if any part matches
    if (correctAnswer.includes('/')) {
        const alternativeAnswers = correctAnswer.split('/').map(s => s.trim());
        if (alternativeAnswers.includes(userAnswer)) {
            isCorrect = true;
        }
    } else if (userAnswer === correctAnswer) {
        isCorrect = true;
    }


    if (isCorrect) {
        feedbackText.textContent = "정답입니다! молодец! (잘했어!) 🎉";
        feedbackText.className = 'feedback-correct';
        points += 10;
        streak++;
        if (!isReviewSession) correctCount++;

        // Bonus points for streaks
        if (streak === 5) {
            points += 20; // Bonus
            showTemporaryEffect(pointsSpan, "✨ +20 보너스! ✨", "points-gain-effect");
            showTemporaryEffect(streakSpan, "🔥 5연속 정답! 🔥", "streak-effect");
        } else if (streak >= 10 && streak % 5 === 0) { // Every 5 correct answers after 10 (10, 15, 20...)
            points += 30; // Consistent bonus for sustained streaks
            showTemporaryEffect(pointsSpan, `🌟 +30 (${streak}연속!) 🌟`, "points-gain-effect");
            showTemporaryEffect(streakSpan, `🚀 ${streak}연속 달성! 🚀`, "streak-effect");
        } else if (streak > 0 && streak < 5 && streak % 3 === 0) { // Bonus at 3
             points += 5;
            showTemporaryEffect(pointsSpan, "👍 +5", "points-gain-effect");
        }


        if (isReviewSession) {
            wordsToReview.splice(currentWordIndex, 1);
            currentWordIndex--; // Adjust index as current item is removed
        }

    } else { // Incorrect Answer
        feedbackText.textContent = `아쉬워요! 정답은 "${currentWordData.word}" 입니다. 😥`;
        feedbackText.className = 'feedback-incorrect';
        streak = 0;
        if (!isReviewSession) {
            incorrectCount++;
            if (!wordsToReview.find(w => w.word === currentWordData.word)) {
                 wordsToReview.push(currentWordData);
            }
        } else {
            // If incorrect in review, move the word to the end of the review list
            const failedWord = wordsToReview.splice(currentWordIndex, 1)[0];
            wordsToReview.push(failedWord);
            currentWordIndex--; // Adjust index as current item is effectively removed from its position
        }
    }

    addToHistory(currentWordData.word, currentWordData.meaning, isCorrect);
    updateStatsDisplay();

    currentWordIndex++;
    // Disable inputs briefly to prevent rapid clicks & show feedback
    spellInput.disabled = true;
    submitAnswerButton.disabled = true;
    hintButton.disabled = true;
    showAnswerButton.disabled = true;

    setTimeout(() => {
        spellInput.disabled = false;
        submitAnswerButton.disabled = false;
        hintButton.disabled = false;
        showAnswerButton.disabled = false;
        displayNextWord();
    }, isCorrect ? 1500 : 2500);
}


/**
 * Shows a hint (first letter).
 */
function showHint() {
    const currentWordData = isReviewSession ? wordsToReview[currentWordIndex] : currentWordSet[currentWordIndex];
    if (currentWordData) {
        const firstLetter = currentWordData.word.charAt(0);
        feedbackText.textContent = `힌트: 첫 글자는 '${firstLetter}' 입니다. 😉`;
        feedbackText.className = '';
        if (points >= 2) points -= 2; else points = 0;
        updateStatsDisplay();
        spellInput.focus(); // Keep focus on input
    }
}

/**
 * Shows the correct answer.
 */
function showAnswer() {
    const currentWordData = isReviewSession ? wordsToReview[currentWordIndex] : currentWordSet[currentWordIndex];
    if (currentWordData) {
        feedbackText.textContent = `정답: ${currentWordData.word} 🤔`;
        feedbackText.className = 'feedback-incorrect'; // Treated as incorrect
        streak = 0;

        if (!isReviewSession) {
            incorrectCount++;
            if (!wordsToReview.find(w => w.word === currentWordData.word)) {
                wordsToReview.push(currentWordData);
            }
        } else {
            // If "show answer" in review, move the word to the end of the review list
            const failedWord = wordsToReview.splice(currentWordIndex, 1)[0];
            wordsToReview.push(failedWord);
            currentWordIndex--; // Adjust index
        }
        if (points >= 5) points -= 5; else points = 0;
        addToHistory(currentWordData.word, currentWordData.meaning, false, true);
        updateStatsDisplay();

        currentWordIndex++;
        spellInput.disabled = true;
        submitAnswerButton.disabled = true;
        hintButton.disabled = true;
        showAnswerButton.disabled = true;

        setTimeout(() => {
            spellInput.disabled = false;
            submitAnswerButton.disabled = false;
            hintButton.disabled = false;
            showAnswerButton.disabled = false;
            displayNextWord();
        }, 2000);
    }
}


/**
 * Starts a review session for incorrectly answered words.
 */
function startReviewSession() {
    isReviewSession = true;
    currentWordIndex = 0;
    flashcardArea.style.display = 'block';
    reviewArea.style.display = 'block';

    const reviewTitle = reviewArea.querySelector('h2');
    if (reviewTitle) {
        reviewTitle.textContent = `틀린 단어 복습 (${wordsToReview.length}개) 🤓`;
    }

    if (wordsToReview.length > 0) {
        wordsToReview.sort(() => Math.random() - 0.5); // Shuffle for each review round
        currentReviewRoundTotal = wordsToReview.length; // Set total for this round's progress
        // totalWordsSpan in the main progress area will show remaining words in this review round
        // correct/incorrect in main progress area are for the original set, not per-review-round
        displayNextWord();
    } else {
        endGame();
    }
}

/**
 * Ends the review session.
 */
function endReviewSession() {
    if (wordsToReview.length > 0) {
        alert(`아직 ${wordsToReview.length}개의 단어가 남았어요! 다시 복습합니다. 화이팅! 💪`);
        startReviewSession();
    } else {
        isReviewSession = false;
        feedbackText.textContent = "모든 단어 복습 완료! 정말 대단해요! 🥳";
        feedbackText.className = 'feedback-correct';
        flashcardArea.style.display = 'none';
        reviewArea.style.display = 'none';
        selectionArea.style.display = 'block';
        historyArea.style.display = 'block';
        updateProgress(); // Final progress update to show 100% if all done
    }
}


/**
 * Ends the current game or set.
 */
function endGame() {
    flashcardArea.style.display = 'none';
    selectionArea.style.display = 'block';
    historyArea.style.display = 'block';
    isReviewSession = false;

    let finalMessage = `학습 완료! 총 ${currentWordSet.length} 단어 중 ${correctCount}개를 맞췄습니다.`;
    if (wordsToReview.length > 0) {
        finalMessage += ` ${wordsToReview.length}개의 단어는 복습이 필요해요!`;
    } else {
        finalMessage += " 모든 단어를 마스터했어요! 축하합니다! 🎉";
    }
    feedbackText.textContent = finalMessage;
    feedbackText.className = ''; // Reset class
    // alert(finalMessage); // Or display it more nicely
}

/**
 * Updates the displayed stats (points, streak, progress).
 */
function updateStatsDisplay() {
    pointsSpan.textContent = points;
    streakSpan.textContent = streak;
    correctWordsSpan.textContent = correctCount;
    incorrectWordsSpan.textContent = incorrectCount;
}

/**
 * Updates the progress bar.
 */
function updateProgress() {
    let percentage = 0;
    let wordsProcessed = 0;
    let totalForProgress = 0;

    if (isReviewSession) {
        totalForProgress = currentReviewRoundTotal; // Total for this specific review round
        wordsProcessed = currentReviewRoundTotal - wordsToReview.length; // How many reviewed in this round
        totalWordsSpan.textContent = wordsToReview.length; // Display remaining words in review
        // correct/incorrect counts in the progress area still refer to the original set
    } else {
        totalForProgress = currentWordSet.length;
        wordsProcessed = currentWordIndex;
        totalWordsSpan.textContent = currentWordSet.length - currentWordIndex; // Remaining in current set
    }

    if (totalForProgress > 0) {
        percentage = (wordsProcessed / totalForProgress) * 100;
    } else if (currentWordSet.length === 0 && wordsToReview.length === 0) { // Handles case where everything is done
        percentage = 100;
    }


    progressBar.style.width = `${percentage}%`;
    progressBar.textContent = `${Math.round(percentage)}%`;

    // Update correct/incorrect counts for the main set always
    correctWordsSpan.textContent = correctCount;
    incorrectWordsSpan.textContent = incorrectCount;
}


/**
 * Adds an entry to the learning history.
 */
function addToHistory(word, meaning, isCorrect, showedAnswer = false) {
    const listItem = document.createElement('li');
    let text = `단어: ${word} (뜻: ${meaning}) - ${isCorrect ? '정답 👍' : (showedAnswer ? '정답확인 💡' : '오답 👎')}`;
    listItem.textContent = text;
    listItem.className = isCorrect ? 'history-correct' : 'history-incorrect';
    historyList.insertBefore(listItem, historyList.firstChild); // Add to top
    if (historyArea.style.display === 'none') {
        historyArea.style.display = 'block';
    }
}

/**
 * Clears the learning history display.
 */
function clearHistory() {
    historyList.innerHTML = '';
}

/**
 * Shows a temporary visual effect on an element.
 */
function showTemporaryEffect(element, message, effectClass) {
    const originalText = element.textContent;
    if (message) element.textContent = message; // Temporarily change text if message is provided
    element.classList.add(effectClass);
    element.addEventListener('animationend', () => {
        element.classList.remove(effectClass);
        if (message) element.textContent = originalText; // Restore original text
    }, { once: true });
}


// --- Initialize ---
document.addEventListener('DOMContentLoaded', initializeApp);
