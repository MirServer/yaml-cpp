#include "yaml-cpp/parser.h"
#include "yaml-cpp/exceptions.h"
#include "mock_event_handler.h"
#include "gtest/gtest.h"

using YAML::Parser;
using YAML::MockEventHandler;
using ::testing::NiceMock;
using ::testing::StrictMock;

TEST(ParserTest, Empty) {
    Parser parser;

    EXPECT_FALSE(parser);

    StrictMock<MockEventHandler> handler;
    EXPECT_FALSE(parser.HandleNextDocument(handler));
}

TEST(ParserTest, CVE_2017_5950) {
    std::string excessive_recursion(16384, '[');
    std::istringstream input{excessive_recursion};
    Parser parser{input};

    NiceMock<MockEventHandler> handler;
    EXPECT_THROW(parser.HandleNextDocument(handler), YAML::ParserException);
}

TEST(ParserTest, CVE_2018_20573) {
    std::string excessive_recursion(20535, '{');
    std::istringstream input{excessive_recursion};
    Parser parser{input};

    NiceMock<MockEventHandler> handler;
    EXPECT_THROW(parser.HandleNextDocument(handler), YAML::ParserException);
}

TEST(ParserTest, CVE_2018_20574) {
    std::string excessive_recursion(21989, '{');
    std::istringstream input{excessive_recursion};
    Parser parser{input};

    NiceMock<MockEventHandler> handler;
    EXPECT_THROW(parser.HandleNextDocument(handler), YAML::ParserException);
}

TEST(ParserTest, CVE_2019_6285) {
    std::string excessive_recursion = std::string(23100, '[') + 'f';
    std::istringstream input{excessive_recursion};
    Parser parser{input};

    NiceMock<MockEventHandler> handler;
    EXPECT_THROW(parser.HandleNextDocument(handler), YAML::ParserException);
}
