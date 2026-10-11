import '../models/community.dart';
import 'location_catalogue.dart';

class DemoSeed {
  DemoSeed({DateTime? now}) : now = (now ?? DateTime.now()).toUtc();
  final DateTime now;
  static const meId = '00000000-0000-4000-8000-000000000001';
  CommunityProfile get me => CommunityProfile(
    id: meId,
    name: 'Anjali Kumari',
    location: demoLocations.first,
    landmark: 'हनुमान मंदिर के पास',
    reputation: 28,
  );

  CommunityProfile person(
    int n,
    String name, {
    int area = 0,
    int reputation = 46,
  }) => CommunityProfile(
    id: '10000000-0000-4000-8000-${n.toString().padLeft(12, '0')}',
    name: name,
    location: demoLocations[area],
    reputation: reputation,
  );
  String postId(int n) =>
      '20000000-0000-4000-8000-${n.toString().padLeft(12, '0')}';

  List<CommunityPost> get posts => [
    CommunityPost(
      id: postId(1),
      author: person(1, 'रवि कुमार'),
      type: PostType.civicIssue,
      title: 'गली में पानी जमा है। साथ मिलकर कुछ करें?',
      description:
          'हनुमान मंदिर वाली गली में बारिश के बाद पानी रुक गया है। पैदल आने-जाने में दिक्कत हो रही है। क्या हम रविवार को मिलकर रास्ता साफ़ कर सकते हैं? जिन पड़ोसियों को भी यह परेशानी है, वे “मेरे यहाँ भी” दबाएँ।',
      location: demoLocations.first,
      metadata: const IssueMetadata(severity: Severity.high, dittoCount: 18),
      createdAt: now.subtract(const Duration(minutes: 23)),
      upvotes: 42,
      commentCount: 3,
      landmark: 'हनुमान मंदिर के पास',
      latitude: 25.600,
      longitude: 85.159,
      mediaUrls: const ['asset:assets/images/waterlogging.jpg'],
    ),
    CommunityPost(
      id: postId(2),
      author: person(2, 'नेहा सिंह'),
      type: PostType.event,
      title: 'इस रविवार, अपने पार्क के लिए एक घंटा 🌱',
      description:
          'छोटे पार्क की सफ़ाई और पौधों की देखभाल के लिए मिलते हैं। दस्ताने और पानी साथ लाएँ। बच्चों और बड़ों, सबका स्वागत है। यह पड़ोसियों की अपनी पहल है, किसी विभाग का कार्यक्रम नहीं।',
      location: demoLocations.first,
      metadata: EventMetadata(
        date: _nextSunday(),
        venue: 'मोहल्ला पार्क, कंकड़बाग',
        rsvpCount: 17,
      ),
      createdAt: now.subtract(const Duration(hours: 1)),
      upvotes: 31,
      landmark: 'मोहल्ला पार्क',
      latitude: 25.598,
      longitude: 85.160,
    ),
    CommunityPost(
      id: postId(3),
      author: person(3, 'अमित राज'),
      type: PostType.localReview,
      title: 'शाम की चाय का नया ठिकाना ☕',
      description:
          'शर्मा जी की कुल्हड़ चाय और गरम समोसे अच्छे लगे। बैठने की जगह थोड़ी कम है, लेकिन दुकान साफ़ है। यह मेरी व्यक्तिगत राय है—कोई paid promotion नहीं। आपने यहाँ की चाय चखी?',
      location: demoLocations.first,
      metadata: const ReviewMetadata(
        businessName: 'शर्मा चाय घर',
        category: 'food',
        rating: 4.5,
      ),
      createdAt: now.subtract(const Duration(hours: 2)),
      upvotes: 26,
      commentCount: 1,
      landmark: 'मुख्य बाज़ार के पास',
      latitude: 25.599,
      longitude: 85.156,
      mediaUrls: const ['asset:assets/images/chai.jpg'],
    ),
    CommunityPost(
      id: postId(4),
      author: person(4, 'पूजा कुमारी'),
      type: PostType.civicIssue,
      title: 'अँधेरी गली में शाम को साथ चलें',
      description:
          'गली के मोड़ पर रोशनी कम है। शाम के समय बुज़ुर्गों और बच्चों को परेशानी होती है। पड़ोसी मिलकर सुरक्षित आने-जाने में मदद करें और अपनी राय साझा करें।',
      location: demoLocations.first,
      metadata: const IssueMetadata(severity: Severity.medium, dittoCount: 9),
      createdAt: now.subtract(const Duration(hours: 4)),
      upvotes: 19,
      landmark: 'गली नंबर 3',
      latitude: 25.597,
      longitude: 85.157,
    ),
    CommunityPost(
      id: postId(5),
      author: person(5, 'सुमन देवी'),
      type: PostType.general,
      title: 'किताबें बाँटें, कहानियाँ जोड़ें 📚',
      description:
          'मेरे पास कक्षा 6–8 की कुछ किताबें हैं। जिन्हें ज़रूरत हो, यहाँ टिप्पणी करें। पैसे या निजी फोन नंबर साझा करने की ज़रूरत नहीं—मिलने की जगह सार्वजनिक रखें।',
      location: demoLocations.first,
      metadata: const GeneralMetadata(),
      createdAt: now.subtract(const Duration(hours: 9)),
      upvotes: 34,
    ),
    CommunityPost(
      id: postId(6),
      author: me,
      type: PostType.civicIssue,
      title: 'पार्क के पास अब रास्ता साफ़ है ✨',
      description:
          'आठ पड़ोसियों ने मिलकर पार्क के बाहर पड़ा कचरा हटाया। साथ देने वाले सभी लोगों का धन्यवाद! सफ़ाई बनाए रखने के लिए कूड़ा डिब्बे में ही डालें।',
      location: demoLocations.first,
      metadata: const IssueMetadata(
        severity: Severity.low,
        resolved: true,
        dittoCount: 6,
      ),
      createdAt: now.subtract(const Duration(days: 1)),
      upvotes: 58,
      landmark: 'मोहल्ला पार्क',
      latitude: 25.598,
      longitude: 85.158,
    ),
    CommunityPost(
      id: postId(7),
      author: person(6, 'रोहित कुमार', area: 1),
      type: PostType.event,
      title: 'राजेंद्र नगर में रविवार का खेल मिलन',
      description:
          'कबड्डी, बैडमिंटन और थोड़ी बातचीत। कोई entry fee नहीं। पास के सभी मोहल्लों के पड़ोसी आ सकते हैं।',
      location: demoLocations[1],
      metadata: EventMetadata(
        date: now.add(const Duration(days: 4)),
        venue: 'स्थानीय खेल मैदान',
        rsvpCount: 12,
      ),
      createdAt: now.subtract(const Duration(hours: 3)),
      upvotes: 22,
      latitude: 25.605,
      longitude: 85.163,
    ),
    CommunityPost(
      id: postId(8),
      author: person(7, 'किरण देवी', area: 4),
      type: PostType.civicIssue,
      title: 'दानारा में रास्ते की मिट्टी बराबर करें',
      description:
          'वार्ड 4 में बरसात से रास्ता ऊबड़-खाबड़ हो गया है। पास के लोग मिलकर बातचीत करें कि सुरक्षित रास्ता कैसे बनाया जाए।',
      location: demoLocations[4],
      metadata: const IssueMetadata(severity: Severity.medium, dittoCount: 7),
      createdAt: now.subtract(const Duration(hours: 2)),
      upvotes: 16,
      latitude: 25.450,
      longitude: 84.880,
    ),
    CommunityPost(
      id: postId(9),
      author: person(8, 'मुकेश यादव', area: 5),
      type: PostType.general,
      title: 'वार्ड 5 में पढ़ाई का छोटा समूह',
      description:
          'बच्चों के लिए शाम का पढ़ाई समूह शुरू कर रहे हैं। जो पड़ोसी हफ़्ते में एक घंटा दे सकें, वे बातचीत में जुड़ें।',
      location: demoLocations[5],
      metadata: const GeneralMetadata(),
      createdAt: now.subtract(const Duration(hours: 7)),
      upvotes: 11,
    ),
    CommunityPost(
      id: postId(10),
      author: person(9, 'संजय कुमार', area: 6),
      type: PostType.general,
      title: 'महजपुरा के पड़ोसी यहाँ मिलें',
      description:
          'यह अलग पंचायत का वार्ड 4 है। दानारा का वार्ड 4 और यह वार्ड एक जैसे नंबर के बावजूद अलग समुदाय हैं।',
      location: demoLocations[6],
      metadata: const GeneralMetadata(),
      createdAt: now.subtract(const Duration(hours: 5)),
      upvotes: 8,
    ),
    CommunityPost(
      id: postId(11),
      author: person(10, 'प्रिया', area: 7),
      type: PostType.event,
      title: 'गया में किताबों की अदला-बदली',
      description:
          'पड़ोसियों के साथ अपनी पढ़ी हुई किताबें बाँटें। अच्छी हालत की किताबें लाएँ और कोई नई कहानी घर ले जाएँ।',
      location: demoLocations[7],
      metadata: EventMetadata(
        date: now.add(const Duration(days: 6)),
        venue: 'स्थानीय सामुदायिक पार्क',
      ),
      createdAt: now.subtract(const Duration(hours: 8)),
      upvotes: 13,
      latitude: 24.791,
      longitude: 85.006,
    ),
  ];

  DateTime _nextSunday() {
    final local = now.toLocal();
    var days = (DateTime.sunday - local.weekday) % 7;
    if (days == 0) days = 7;
    return DateTime(local.year, local.month, local.day + days, 8).toUtc();
  }

  List<ThreadComment> get comments {
    final first = '30000000-0000-4000-8000-000000000001';
    return [
      ThreadComment(
        id: first,
        postId: postId(1),
        author: person(2, 'नेहा सिंह'),
        content: 'मेरे घर के सामने भी यही हाल है। रविवार सुबह मैं आ सकती हूँ।',
        createdAt: now.subtract(const Duration(minutes: 18)),
      ),
      ThreadComment(
        id: '30000000-0000-4000-8000-000000000002',
        postId: postId(1),
        author: person(1, 'रवि कुमार'),
        parentId: first,
        content: 'धन्यवाद नेहा जी! सुबह 8 बजे मंदिर के पास मिलते हैं।',
        createdAt: now.subtract(const Duration(minutes: 14)),
      ),
      ThreadComment(
        id: '30000000-0000-4000-8000-000000000003',
        postId: postId(1),
        author: person(4, 'पूजा कुमारी'),
        content: 'मैं झाड़ू और दस्ताने ले आऊँगी।',
        createdAt: now.subtract(const Duration(minutes: 8)),
      ),
      ThreadComment(
        id: '30000000-0000-4000-8000-000000000004',
        postId: postId(3),
        author: person(5, 'सुमन देवी'),
        content:
            'अदरक वाली चाय अच्छी है। बच्चों के लिए कम चीनी भी बना देते हैं।',
        createdAt: now.subtract(const Duration(minutes: 40)),
      ),
    ];
  }
}
