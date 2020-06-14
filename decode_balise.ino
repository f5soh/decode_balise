/*
    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */
/*
 * Packet sniffer
 * 
 * Reçoit et décode les données émises par une balise et les affiche dans la console.
 * 
 * Fonctionne avec n'importe quelle carte à base ESP32 et https://github.com/esp8266/Arduino
 * 
 * ** Limitation du SDK : la trame ne peut être décodée en totalité (ID, LAT, LONG et AlT si ssid court) **
 */

#include <Arduino.h>

extern "C" {
  #include <user_interface.h>
}

#define DATA_LENGTH           112

#define TYPE_MANAGEMENT       0x00
#define TYPE_CONTROL          0x01
#define TYPE_DATA             0x02
#define SUBTYPE_PROBE_REQUEST 0x04

struct RxControl {
 signed rssi:8; // signal intensity of packet
 unsigned rate:4;
 unsigned is_group:1;
 unsigned:1;
 unsigned sig_mode:2; // 0:is 11n packet; 1:is not 11n packet;
 unsigned legacy_length:12; // if not 11n packet, shows length of packet.
 unsigned damatch0:1;
 unsigned damatch1:1;
 unsigned bssidmatch0:1;
 unsigned bssidmatch1:1;
 unsigned MCS:7; // if is 11n packet, shows the modulation and code used (range from 0 to 76)
 unsigned CWB:1; // if is 11n packet, shows if is HT40 packet or not
 unsigned HT_length:16;// if is 11n packet, shows length of packet.
 unsigned Smoothing:1;
 unsigned Not_Sounding:1;
 unsigned:1;
 unsigned Aggregation:1;
 unsigned STBC:2;
 unsigned FEC_CODING:1; // if is 11n packet, shows if is LDPC packet or not.
 unsigned SGI:1;
 unsigned rxend_state:8;
 unsigned ampdu_cnt:8;
 unsigned channel:6; //which channel this packet in.
 unsigned:12;
};

struct SnifferPacket{
    struct RxControl rx_ctrl;
    uint8_t data[DATA_LENGTH];
    uint16_t cnt;
    uint16_t len;
};

    /**
     * Enumeration des types de données à envoyer
     */
    enum DATA_TYPE: uint8_t {
      RESERVED = 0,
      PROTOCOL_VERSION = 1,
      ID_FR = 2,
      ID_ANSI_CTA = 3,
      LATITUDE = 4,        // In WS84 in degree * 1e5
      LONGITUDE = 5,       // In WS84 in degree * 1e5
      ALTITUDE = 6,        // In MSL in m
      HEIGTH = 7,          // From Home in m
      HOME_LATITUDE = 8,   // In WS84 in degree * 1e5
      HOME_LONGITUDE = 9,  // In WS84 in degree * 1e5
      GROUND_SPEED = 10,   // In m/s
      HEADING = 11,        // Heading in degree from north 0 to 359.
      NOT_DEFINED_END = 12,
    };

    /**
     * Tableau TLV (TYPE, LENGTH, VALUE) avec les tailles attendu des différents type données.
     */
    static constexpr uint8_t TLV_LENGTH[] {
            0,  // [DATA_TYPE::RESERVED]
            1,  // [DATA_TYPE::PROTOCOL_VERSION]
            30, // [DATA_TYPE::ID_FR]
            0,  // [DATA_TYPE::ID_ANSI_CTA]
            4,  // [DATA_TYPE::LATITUDE]
            4,  // [DATA_TYPE::LONGITUDE]
            2,  // [DATA_TYPE::ALTITUDE]
            2,  // [DATA_TYPE::HEIGTH]
            4,  // [DATA_TYPE::HOME_LATITUDE]
            4,  // [DATA_TYPE::HOME_LONGITUDE]
            1,  // [DATA_TYPE::GROUND_SPEED]
            2,  // [DATA_TYPE::HEADING]
    };


static void showMetadata(SnifferPacket *snifferPacket) {

  unsigned int frameControl = ((unsigned int)snifferPacket->data[1] << 8) + snifferPacket->data[0];

  //uint8_t version      = (frameControl & 0b0000000000000011) >> 0;
  uint8_t frameType    = (frameControl & 0b0000000000001100) >> 2;
  uint8_t frameSubType = (frameControl & 0b0000000011110000) >> 4;
  //uint8_t toDS         = (frameControl & 0b0000000100000000) >> 8;
  //uint8_t fromDS       = (frameControl & 0b0000001000000000) >> 9;

  //Serial.print(frameSubType);

 
  // Only look for probe request packets
  //if (//frameType != TYPE_MANAGEMENT ||
      //frameSubType != SUBTYPE_PROBE_REQUEST || 
  //  frameType != 3 || frameSubType != 15)
  //    return;
  
  
  uint8_t SSID_length = snifferPacket->data[40-4];
  uint8_t offset_OUI = 41-4+SSID_length+1;

  const uint8_t FRAME_OUI[3] = {0x6A, 0x5C, 0x35};

  // Filter OUI from 6A:5C:35
  if(snifferPacket->data[offset_OUI+1] != FRAME_OUI[0] && snifferPacket->data[offset_OUI+2] != FRAME_OUI[1] && snifferPacket->data[offset_OUI+3] != FRAME_OUI[2])
     return;
     


  //char addr[] = "00:00:00:00:00:00";
  //getMAC(addr, snifferPacket->data, 10);

  // Informations supplémentaires
  //Serial.print(" RSSI: "); Serial.print(snifferPacket->rx_ctrl.rssi, DEC);
  //Serial.print(" Ch: "); Serial.print(wifi_get_channel());
  //Serial.print(" MAC: "); Serial.print(addr);      
  //Serial.print(" AP: ");  printDataSpan(41-4, SSID_length, snifferPacket->data);

  // ID balise
  Serial.print(" ID: ");  printDataSpan(offset_OUI+4+6, TLV_LENGTH[ID_FR] , snifferPacket->data);
  uint16_t offset = offset_OUI+4+6+TLV_LENGTH[ID_FR]+2; // +2 : Type + Lenght

  // Latitude
  Serial.print(" LAT: "); printCoordinates(offset, TLV_LENGTH[LATITUDE] , snifferPacket->data); 
  offset += TLV_LENGTH[LATITUDE]+2;
  
  // Longitude  
  Serial.print(" LON: "); printCoordinates(offset, TLV_LENGTH[LONGITUDE] , snifferPacket->data); //Serial.println();
  offset += TLV_LENGTH[LONGITUDE]+2;

  //Altitude msl
  Serial.print(" ALTmsl: "); printAltitude(offset, TLV_LENGTH[ALTITUDE] , snifferPacket->data); Serial.println();
  //offset += TLV_LENGTH[ALTITUDE]+2;

  //Serial.print(" AltHome: "); printAltitude(offset, TLV_LENGTH[HEIGTH] , snifferPacket->data); Serial.println();
  //offset += TLV_LENGTH[HEIGTH]+2;
  
  //Serial.print(" offset= ");Serial.println(offset);
  //Serial.print("\t [");

  //Serial.print(snifferPacket->len);

  //Serial.print("");

  // trame test
  //80 0 0 0 FF FF FF FF FF FF 1 2 3 4 5 6 1 2 3 4 5 6 0 0 83 51 F7 8F F 0 0 0 E8 3 21 4 3 1 6 0 10 49 4C 4C 45 47 41 4C 5F 44 52 4F 4E 45 5F 41 50 DD 4E 6A 5C 35 1 1 1 1 2 1E 49 4C 4C 45 47 41 4C 5F 44 52 4F 4E 45 5F 41 50 50 45 4C 45 5A 5F 50 4F 4C 49 43 45 31 37 4 4 0 42 23 E7 5 4 FF FE C2 AE 
  //Serial.println("T 6 2 0 7B 7 2 0 19 8 4 0 0 0 0 9 4 0 0 0 0 A 1 2C B 2 0 21");
  
  /*
   
  Serial.println("T 6\t2\t0\t7B\t7\t2\t0\t19\t8\t4\t0\t0\t0\t0\t9\t4\t0\t0\t0\t0\tA\t1\t2C\tB\t2\t0\t21");
  
  Serial.print("R ");
  for (auto i=0; i<24;i++) {

 
  Serial.print(snifferPacket->data[offset-2+i], HEX);
  Serial.print("\t");
  
  } 
  Serial.println();
  
  */
  
  /* Serial.print(" HAUT: "); printValueSpan(offset, TLV_LENGTH[HEIGTH] , snifferPacket->data); 
  offset += TLV_LENGTH[HEIGTH];

  Serial.print(" HLAT: "); printValueSpan(offset, TLV_LENGTH[HOME_LATITUDE] , snifferPacket->data); 
  offset += TLV_LENGTH[HOME_LATITUDE];
  
  Serial.print(" HLON: "); printValueSpan(offset, TLV_LENGTH[HOME_LONGITUDE] , snifferPacket->data); 
  offset += TLV_LENGTH[HOME_LONGITUDE];

  Serial.print(" VIT: "); printValueSpan(offset, TLV_LENGTH[GROUND_SPEED] , snifferPacket->data); 
  offset += TLV_LENGTH[GROUND_SPEED];
  
  Serial.print(" DIR: "); printValueSpan(offset, TLV_LENGTH[HEADING] , snifferPacket->data); 
  offset += TLV_LENGTH[HEADING];
  */
    
     
    /*    for (auto i=0; i<sizeof(snifferPacket->data);i++) {
            Serial.print(snifferPacket->data[i], HEX);
            Serial.print(" ");
        } */
 
}

/**
 * Callback for promiscuous mode
 */
static void ICACHE_FLASH_ATTR sniffer_callback(uint8_t *buffer, uint16_t length) {
  struct SnifferPacket *snifferPacket = (struct SnifferPacket*) buffer;
  showMetadata(snifferPacket);
}

static void printDataSpan(uint16_t start, uint16_t size, uint8_t* data) {
  for(uint16_t i = start; i < DATA_LENGTH && i < start+size; i++) {
    Serial.write(data[i]);
  }
}

static void printCoordinates(uint16_t start, uint16_t size, uint8_t* data) {
  uint8_t count = size-1;
  int data_value = 0;
  //Serial.print(" data_value="); Serial.print(data_value); Serial.print(" neg=");
  bool neg_number = data[start] > 0x7F;
  //Serial.print(neg_number);Serial.print(" ");
  
  for(uint16_t i = start; i < DATA_LENGTH && i < start+size; i++) {
     //Serial.print(count); Serial.print("-");  
     data_value +=  (data[i]) << (8 * count); 
     count--;
  }

  if(neg_number) {
    data_value = (0xFFFFFFFF & ~data_value) + 1; 
    data_value *= -1;
  }
  
  Serial.print(double(data_value) * 0.00001 , 5);
}


static void printAltitude(uint16_t start, uint16_t size, uint8_t* data) {
  uint8_t count = size-1;
  int data_value = 0;
  bool neg_number = data[start] > 0x7F;
  //Serial.print(neg_number);Serial.print(" ");
  
  for(uint16_t i = start; i < DATA_LENGTH && i < start+size; i++) {
     //Serial.print(count); Serial.print("-");  
     data_value +=  (data[i]) << (8 * count); 
     count--;
  }

  if(neg_number) {
    data_value = (0xFFFF & ~data_value) + 1; 
    data_value *= -1;
  }
  
  Serial.print(data_value);
}
static void getMAC(char *addr, uint8_t* data, uint16_t offset) {
  sprintf(addr, "%02x:%02x:%02x:%02x:%02x:%02x", data[offset+0], data[offset+1], data[offset+2], data[offset+3], data[offset+4], data[offset+5]);
}


#define DISABLE 0
#define ENABLE  1

void setup() {
  // set the WiFi chip to "promiscuous" mode aka monitor mode
  Serial.begin(115200);
  delay(10);
  wifi_set_opmode(STATION_MODE);
  wifi_set_channel(6);
  wifi_promiscuous_enable(DISABLE);
  delay(10);
  wifi_set_promiscuous_rx_cb(sniffer_callback);
  delay(10);
  wifi_promiscuous_enable(ENABLE);
}

void loop() {
  delay(10); 
}
