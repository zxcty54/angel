enum AreaType { urban, rural }

enum FeedScope { ward, area, block, district }

enum FeedSort { latest, supported }

/// A ward is identified by its COMPLETE administrative path, not ward number.
/// Rural Ward 4 in Danara is not Ward 4 in a different panchayat.
class AreaPath {
  const AreaPath({
    required this.id,
    required this.district,
    required this.areaType,
    required this.blockOrUlb,
    this.panchayat,
    required this.ward,
    required this.alias,
    this.latitude,
    this.longitude,
  });

  final int id;
  final String district;
  final AreaType areaType;
  final String blockOrUlb;
  final String? panchayat;
  final int ward;
  final String alias;
  final double? latitude;
  final double? longitude;

  bool get isRural => areaType == AreaType.rural;
  String get areaName => isRural ? panchayat! : blockOrUlb;
  String get shortLabel => alias.isEmpty ? 'Ward $ward' : alias;
  String get fullLabel =>
      '$district · $blockOrUlb'
      '${isRural ? ' · $panchayat' : ''} · Ward $ward';
  String get identity =>
      '$district|${areaType.name}|$blockOrUlb|${panchayat ?? ''}|$ward';

  bool contains(AreaPath other, FeedScope scope) {
    if (district != other.district) return false;
    if (scope == FeedScope.district) return true;
    if (areaType != other.areaType || blockOrUlb != other.blockOrUlb) {
      return false;
    }
    if (scope == FeedScope.block) return true;
    if (panchayat != other.panchayat) return false;
    if (scope == FeedScope.area) return true;
    return ward == other.ward;
  }

  Map<String, dynamic> toJson() => {
    'id': id,
    'district': district,
    'area_type': areaType.name,
    'block_or_ulb': blockOrUlb,
    'panchayat_name': panchayat,
    'ward_number': ward,
    'ward_alias': alias,
    'latitude': latitude,
    'longitude': longitude,
  };

  factory AreaPath.fromJson(Map<String, dynamic> json) => AreaPath(
    id: (json['id'] as num).toInt(),
    district: json['district'] as String,
    areaType: AreaType.values.byName(json['area_type'] as String),
    blockOrUlb: json['block_or_ulb'] as String,
    panchayat: json['panchayat_name'] as String?,
    ward: (json['ward_number'] as num).toInt(),
    alias: (json['ward_alias'] ?? '') as String,
    latitude: (json['latitude'] as num?)?.toDouble(),
    longitude: (json['longitude'] as num?)?.toDouble(),
  );

  @override
  bool operator ==(Object other) =>
      other is AreaPath && identity == other.identity;
  @override
  int get hashCode => identity.hashCode;
}

class FeedQuery {
  const FeedQuery({
    required this.location,
    this.scope = FeedScope.ward,
    this.type,
    this.search = '',
    this.sort = FeedSort.latest,
    this.limit = 20,
  });
  final AreaPath location;
  final FeedScope scope;
  final String? type;
  final String search;
  final FeedSort sort;
  final int limit;
}

class FeedCursor {
  const FeedCursor(this.createdAt, this.id, this.upvotes);
  final DateTime createdAt;
  final String id;
  final int upvotes;
}
