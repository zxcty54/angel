import 'package:flutter/material.dart';
import 'package:provider/provider.dart';
import '../../controllers/app_controller.dart';
import '../../models/community.dart';
import '../../models/location.dart';
import '../../theme/app_theme.dart';
import '../widgets/common.dart';
import '../widgets/post_card.dart';

class CommunityScreen extends StatefulWidget {
  const CommunityScreen({
    super.key,
    required this.onCreateEvent,
    required this.onPost,
  });
  final VoidCallback onCreateEvent;
  final void Function(CommunityPost) onPost;
  @override
  State<CommunityScreen> createState() => _CommunityScreenState();
}

class _CommunityScreenState extends State<CommunityScreen> {
  String? _key;
  Future<FeedPage>? _events;
  @override
  void didChangeDependencies() {
    super.didChangeDependencies();
    final c = context.watch<AppController>();
    if (_key != c.selectedLocation!.identity) {
      _key = c.selectedLocation!.identity;
      _events = c.repository.getFeed(
        FeedQuery(
          location: c.selectedLocation!,
          scope: FeedScope.area,
          type: PostType.event.key,
          limit: 10,
        ),
      );
    }
  }

  @override
  Widget build(BuildContext context) {
    final c = context.watch<AppController>();
    return ListView(
      padding: const EdgeInsets.fromLTRB(22, 26, 22, 90),
      children: [
        SectionHeading(
          c.text('मिलकर मोहल्ला बनाएँ', 'Small acts. Real community.'),
          subtitle: c.text(
            'यहाँ पड़ोसी एक-दूसरे का साथ देते हैं।',
            'A community is something we do, together.',
          ),
        ),
        const SizedBox(height: 22),
        Container(
          padding: const EdgeInsets.all(22),
          decoration: BoxDecoration(
            color: MCColors.ink,
            borderRadius: BorderRadius.circular(20),
          ),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              const Icon(
                Icons.volunteer_activism_outlined,
                color: Color(0xFFBCD5AA),
                size: 34,
              ),
              const SizedBox(height: 14),
              Text(
                c.text(
                  'सरकारी टिकट नहीं।\nअपने लोगों की अपनी पहल।',
                  'People, not paperwork.\nNeighbours, not ticket numbers.',
                ),
                style: const TextStyle(
                  fontSize: 23,
                  fontWeight: FontWeight.w800,
                  height: 1.5,
                  color: Colors.white,
                ),
              ),
              const SizedBox(height: 10),
              Text(
                c.text(
                  'सफ़ाई, किताबें, खेल या कोई अच्छी बात—एक छोटा कार्यक्रम शुरू करें और पड़ोसियों को जोड़ें।',
                  'A clean-up, a book swap, a game in the park. Start something small and bring your neighbours along.',
                ),
                style: const TextStyle(
                  color: Color(0xFFD1DDD1),
                  fontSize: 12,
                  height: 1.8,
                ),
              ),
              const SizedBox(height: 20),
              FilledButton.icon(
                onPressed: widget.onCreateEvent,
                style: FilledButton.styleFrom(
                  backgroundColor: Colors.white,
                  foregroundColor: MCColors.ink,
                ),
                icon: const Icon(Icons.add, size: 18),
                label: Text(
                  c.text('एक पहल शुरू करें', 'Bring people together'),
                ),
              ),
            ],
          ),
        ),
        const SizedBox(height: 24),
        Row(
          children: [
            Expanded(
              child: _ImpactCard(
                value: '${c.stats.resolved}',
                label: c.text('सुलझा हुआ मुद्दा', 'Resolved issues'),
                icon: Icons.task_alt,
                color: MCColors.green,
              ),
            ),
            const SizedBox(width: 12),
            Expanded(
              child: _ImpactCard(
                value: '${c.stats.neighbours}',
                label: c.text('इस वार्ड के पड़ोसी', 'Neighbours in this ward'),
                icon: Icons.people_outline,
                color: MCColors.primary,
              ),
            ),
          ],
        ),
        if (c.isDemo)
          Padding(
            padding: const EdgeInsets.only(top: 10),
            child: Text(
              c.text(
                'ऊपर के आँकड़े केवल स्थानीय demo fixtures से हैं।',
                'These figures are from local demo fixtures only.',
              ),
              style: const TextStyle(fontSize: 10, color: MCColors.muted),
            ),
          ),
        const SizedBox(height: 28),
        Text(
          c.text('आसपास मिलने का अगला मौका', 'A good reason to get together'),
          style: const TextStyle(fontSize: 17, fontWeight: FontWeight.w800),
        ),
        const SizedBox(height: 5),
        Text(
          c.text(
            'आपकी पंचायत / नगर निकाय के कार्यक्रम',
            'Events in your panchayat / urban local body',
          ),
          style: const TextStyle(color: MCColors.muted, fontSize: 11),
        ),
        const SizedBox(height: 14),
        FutureBuilder<FeedPage>(
          future: _events,
          builder: (context, snapshot) {
            if (snapshot.hasError) {
              return EmptyState(
                title: c.text(
                  'कार्यक्रम लोड नहीं हुए',
                  'Could not load events',
                ),
                message: AppController.friendlyError(snapshot.error!),
                action: () {
                  setState(() {
                    _key = null;
                  });
                  didChangeDependencies();
                },
                actionLabel: c.text('फिर कोशिश', 'Retry'),
              );
            }
            if (!snapshot.hasData) {
              return const Center(
                child: Padding(
                  padding: EdgeInsets.all(28),
                  child: CircularProgressIndicator(strokeWidth: 2),
                ),
              );
            }
            final events = snapshot.data!.posts
                .where((p) => !(p.metadata as EventMetadata).hasEnded)
                .toList();
            if (events.isEmpty) {
              return EmptyState(
                title: c.text(
                  'एक नया कार्यक्रम शुरू करें',
                  'Make the first plan',
                ),
                message: c.text(
                  'अभी कोई आने वाला कार्यक्रम नहीं। आपका छोटा विचार शुरुआत बन सकता है।',
                  'There are no upcoming events here yet. Your idea could be the start.',
                ),
                action: widget.onCreateEvent,
                actionLabel: c.text('कार्यक्रम बनाएँ', 'Create an event'),
                icon: Icons.event_available_outlined,
              );
            }
            return Column(
              children: events
                  .map(
                    (p) => Padding(
                      padding: const EdgeInsets.only(bottom: 16),
                      child: PostCard(post: p, onOpen: () => widget.onPost(p)),
                    ),
                  )
                  .toList(),
            );
          },
        ),
        const SizedBox(height: 16),
        Text(
          c.text(
            'अच्छे पड़ोसी होने के कुछ नियम',
            'A few things good neighbours do',
          ),
          style: const TextStyle(fontSize: 17, fontWeight: FontWeight.w800),
        ),
        const SizedBox(height: 14),
        for (final item in [
          (
            Icons.favorite_border,
            c.text('सम्मान से बात करें', 'Be kind, even when you disagree'),
            c.text(
              'व्यक्ति नहीं, बात पर चर्चा करें। नफ़रत और उत्पीड़न के लिए जगह नहीं।',
              'Discuss the idea, not the person. No hate or harassment.',
            ),
          ),
          (
            Icons.privacy_tip_outlined,
            c.text('अपनी निजता बचाएँ', 'Keep personal details private'),
            c.text(
              'फोन नंबर, पूरा घर का पता या किसी की निजी तस्वीर बिना अनुमति न डालें।',
              'Never post phone numbers, exact home addresses or someone’s photo without consent.',
            ),
          ),
          (
            Icons.fact_check_outlined,
            c.text('पहले जाँचें, फिर साझा करें', 'Check before you share'),
            c.text(
              'व्यक्तिगत अनुभव और सत्यापित जानकारी में फ़र्क़ साफ़ रखें।',
              'Be clear about what is your experience and what is verified information.',
            ),
          ),
          (
            Icons.groups_outlined,
            c.text('सुरक्षित जगह पर मिलें', 'Meet in a safe, public place'),
            c.text(
              'पैसे, OTP और पहचान के दस्तावेज़ अजनबियों को न दें। आपातस्थिति में स्थानीय सहायता लें।',
              'Do not share money, OTPs or ID documents with strangers. Seek local help in an emergency.',
            ),
          ),
        ])
          Padding(
            padding: const EdgeInsets.only(bottom: 10),
            child: Container(
              padding: const EdgeInsets.all(16),
              decoration: BoxDecoration(
                color: Colors.white,
                borderRadius: BorderRadius.circular(14),
                border: Border.all(color: MCColors.border),
              ),
              child: Row(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Icon(item.$1, size: 22, color: MCColors.green),
                  const SizedBox(width: 14),
                  Expanded(
                    child: Column(
                      crossAxisAlignment: CrossAxisAlignment.start,
                      children: [
                        Text(
                          item.$2,
                          style: const TextStyle(
                            fontWeight: FontWeight.w800,
                            fontSize: 12,
                          ),
                        ),
                        const SizedBox(height: 5),
                        Text(
                          item.$3,
                          style: const TextStyle(
                            color: MCColors.muted,
                            fontSize: 11,
                            height: 1.8,
                          ),
                        ),
                      ],
                    ),
                  ),
                ],
              ),
            ),
          ),
      ],
    );
  }
}

class _ImpactCard extends StatelessWidget {
  const _ImpactCard({
    required this.value,
    required this.label,
    required this.icon,
    required this.color,
  });
  final String value;
  final String label;
  final IconData icon;
  final Color color;
  @override
  Widget build(BuildContext context) => Container(
    padding: const EdgeInsets.all(18),
    decoration: BoxDecoration(
      color: Colors.white,
      borderRadius: BorderRadius.circular(16),
      border: Border.all(color: MCColors.border),
    ),
    child: Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Icon(icon, color: color),
        const SizedBox(height: 12),
        Text(
          value,
          style: const TextStyle(fontWeight: FontWeight.w800, fontSize: 28),
        ),
        const SizedBox(height: 4),
        Text(
          label,
          style: const TextStyle(fontSize: 11, color: MCColors.muted),
        ),
      ],
    ),
  );
}
