import 'dart:typed_data';
import 'package:flutter_test/flutter_test.dart';
import 'package:mohalla_charcha/data/demo_seed.dart';
import 'package:mohalla_charcha/data/location_catalogue.dart';
import 'package:mohalla_charcha/models/community.dart';
import 'package:mohalla_charcha/models/location.dart';

PostDraft draft({
  PostType type = PostType.general,
  PostMetadata metadata = const GeneralMetadata(),
  String title = 'A local conversation',
  String description = 'A useful thought for our neighbours.',
  double? latitude,
  double? longitude,
  List<Uint8List> images = const [],
}) => PostDraft(
  type: type,
  title: title,
  description: description,
  location: demoLocations.first,
  metadata: metadata,
  latitude: latitude,
  longitude: longitude,
  images: images,
);

void main() {
  group('Administrative hierarchy', () {
    test('all 38 district names are unique', () {
      expect(biharDistricts.length, 38);
      expect(biharDistricts.toSet().length, 38);
    });
    test('rural wards with the same number do not mix', () {
      final danara = demoLocations[4];
      final mahajpura = demoLocations[6];
      expect(danara.ward, mahajpura.ward);
      expect(danara.contains(mahajpura, FeedScope.ward), isFalse);
      expect(danara.contains(mahajpura, FeedScope.area), isFalse);
      expect(danara.contains(mahajpura, FeedScope.block), isTrue);
    });
    test('panchayat contains its wards, but not another panchayat', () {
      expect(
        demoLocations[4].contains(demoLocations[5], FeedScope.area),
        isTrue,
      );
      expect(
        demoLocations[4].contains(demoLocations[5], FeedScope.ward),
        isFalse,
      );
    });
    test('district expands intentionally across urban and rural', () {
      expect(
        demoLocations.first.contains(demoLocations[4], FeedScope.district),
        isTrue,
      );
      expect(
        demoLocations.first.contains(demoLocations[7], FeedScope.district),
        isFalse,
      );
    });
    test('urban ULB scope excludes a different ULB', () {
      expect(
        demoLocations.first.contains(demoLocations[1], FeedScope.area),
        isTrue,
      );
      expect(
        demoLocations.first.contains(demoLocations[3], FeedScope.area),
        isFalse,
      );
    });
    test('path round trips without losing rural panchayat', () {
      final a = demoLocations[4];
      expect(AreaPath.fromJson(a.toJson()), a);
      expect(AreaPath.fromJson(a.toJson()).panchayat, 'Danara');
    });
  });
  group('Unified typed posts', () {
    test('all four types round-trip with typed metadata', () {
      for (final p in DemoSeed().posts) {
        final copy = CommunityPost.fromJson(p.toJson());
        expect(copy.type, p.type);
        expect(copy.metadata.runtimeType, p.metadata.runtimeType);
        expect(copy.metadata.toJson(), p.metadata.toJson());
        expect(copy.location, p.location);
      }
    });
    test(
      'a valid general draft passes',
      () => expect(draft().validate, returnsNormally),
    );
    test(
      'short title rejected',
      () => expect(draft(title: 'Hi').validate, throwsArgumentError),
    );
    test(
      'short description rejected',
      () => expect(draft(description: 'Hi').validate, throwsArgumentError),
    );
    test(
      'wrong metadata rejected',
      () => expect(draft(type: PostType.event).validate, throwsArgumentError),
    );
    test(
      'out-of-range review rating rejected',
      () => expect(
        draft(
          type: PostType.localReview,
          metadata: const ReviewMetadata(
            businessName: 'Shop',
            category: 'food',
            rating: 6,
          ),
        ).validate,
        throwsArgumentError,
      ),
    );
    test(
      'half-star rating required',
      () => expect(
        draft(
          type: PostType.localReview,
          metadata: const ReviewMetadata(
            businessName: 'Shop',
            category: 'food',
            rating: 2.7,
          ),
        ).validate,
        throwsArgumentError,
      ),
    );
    test(
      'unknown review category rejected',
      () => expect(
        draft(
          type: PostType.localReview,
          metadata: const ReviewMetadata(
            businessName: 'Shop',
            category: 'unknown',
            rating: 4,
          ),
        ).validate,
        throwsArgumentError,
      ),
    );
    test(
      'past event rejected',
      () => expect(
        draft(
          type: PostType.event,
          metadata: EventMetadata(
            date: DateTime.now().subtract(const Duration(days: 1)),
            venue: 'Park',
          ),
        ).validate,
        throwsArgumentError,
      ),
    );
    test('future event stores UTC', () {
      final m = EventMetadata(
        date: DateTime.now().add(const Duration(days: 3)),
        venue: 'Park',
      );
      expect(
        draft(type: PostType.event, metadata: m).validate,
        returnsNormally,
      );
      expect((m.toJson()['event_date'] as String).endsWith('Z'), isTrue);
    });
    test('coordinate pair and finite ranges enforced', () {
      expect(draft(latitude: 25.6).validate, throwsArgumentError);
      expect(
        draft(latitude: double.nan, longitude: 85).validate,
        throwsArgumentError,
      );
      expect(draft(latitude: 95, longitude: 85).validate, throwsArgumentError);
      expect(draft(latitude: 25.6, longitude: 85.1).validate, returnsNormally);
    });
    test('image count and byte limits enforced', () {
      expect(
        draft(images: List.generate(4, (_) => Uint8List(1))).validate,
        throwsArgumentError,
      );
      expect(
        draft(images: [Uint8List(12 * 1024 * 1024 + 1)]).validate,
        throwsArgumentError,
      );
    });
  });
}
