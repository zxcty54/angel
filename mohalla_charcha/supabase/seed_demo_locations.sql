-- OPT-IN TEST PROJECT ONLY. These mappings/centroids are ILLUSTRATIVE, NOT official.
-- Never treat this as a complete or certified administrative boundary dataset.
BEGIN;
INSERT INTO public.bl_locations(id,district,area_type,block_or_ulb,panchayat_name,ward_number,ward_alias,latitude,longitude) VALUES
(1,'Patna','urban','Patna Municipal Corporation',NULL,22,'कंकड़बाग',25.5992,85.1580),
(2,'Patna','urban','Patna Municipal Corporation',NULL,23,'राजेंद्र नगर',25.6050,85.1630),
(3,'Patna','urban','Patna Municipal Corporation',NULL,21,'लोहिया नगर',25.5940,85.1550),
(4,'Patna','urban','Danapur Nagar Parishad',NULL,4,'दानापुर',25.6360,85.0410),
(101,'Patna','rural','Bikram','Danara',4,'दानारा',25.4500,84.8800),
(102,'Patna','rural','Bikram','Danara',5,'दानारा पश्चिम',25.4480,84.8750),
(103,'Patna','rural','Bikram','Mahajpura',4,'महजपुरा',25.4580,84.8690),
(201,'Gaya','urban','Gaya Municipal Corporation',NULL,14,'गया मोहल्ला',24.7910,85.0060),
(202,'Gaya','rural','Bodh Gaya','Bakraur',4,'बकरौर',24.6920,84.9970),
(301,'Muzaffarpur','urban','Muzaffarpur Municipal Corporation',NULL,14,'तिलक मैदान रोड',26.1200,85.3910),
(401,'Darbhanga','urban','Darbhanga Municipal Corporation',NULL,10,'दरभंगा मोहल्ला',26.1540,85.8910),
(501,'Bhagalpur','urban','Bhagalpur Municipal Corporation',NULL,16,'भागलपुर मोहल्ला',25.2460,86.9840)
ON CONFLICT(id) DO NOTHING;
SELECT setval(pg_get_serial_sequence('public.bl_locations','id'),greatest(1,(SELECT max(id) FROM public.bl_locations)));
COMMIT;
